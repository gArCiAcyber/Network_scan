"""Terminal formatting helpers for optional live Nmap service scans."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
import ipaddress
from core.terminal import escape_controls, wrap_report

from modules.nmap_xml import NmapXmlImport, format_service_version, require_single_up_host


@dataclass(frozen=True)
class NmapEnrichmentResult:
    """Structured result for optional live Nmap service scan evidence."""

    status: str
    target: str
    ports_requested: tuple[int, ...]
    terminal_text: str
    import_result: NmapXmlImport | None = None
    reason: str | None = None
    runs: tuple["NmapEnrichmentResult", ...] = ()
    execution: dict = field(default_factory=dict)
    elapsed_seconds: float | None = None
    timeout_seconds: float | None = None


def format_nmap_enrichment_summary(
    import_result: NmapXmlImport,
    target: str,
    ports: Sequence[int],
    *,
    status: str | None = None,
    elapsed_seconds: float | None = None,
    timeout_seconds: float | None = None,
) -> str:
    """Return a concise follow-up summary for a live Nmap scan."""
    lines = ["Nmap service scan"]
    if timeout_seconds is not None:
        lines.append(format_nmap_deadline(timeout_seconds))
    lines.extend([format_nmap_run(target, ports,
                 status or ("completed" if import_result.metadata.finished_exit == "success" else "partial"),
                 elapsed_seconds),
             *nmap_evidence_lines(import_result, ports)])
    lines.extend(nmap_warning_lines(import_result.execution.get("stderr", "")))
    return wrap_report(escape_controls("\n".join(lines).rstrip(), multiline=True))


def nmap_evidence_lines(import_result: NmapXmlImport, ports: Sequence[int]) -> list[str]:
    host = require_single_up_host(import_result)
    lines = ["", f"{'PORT':<10} {'STATE':<6} {'SERVICE':<9} VERSION"]
    for port in host.tcp_ports or host.open_tcp_ports:
        service = port.service
        version = format_service_version(service)
        lines.append(f"{str(port.port) + '/tcp':<10} {port.state:<6} "
                     f"{service.name or 'unknown':<9} {version}")
    if any(port.state != "open" for port in host.tcp_ports):
        lines.append("  Nmap observed different states; native evidence retained.")
    missing = sorted(set(ports) - {port.port for port in host.tcp_ports})
    if missing:
        lines.append(f"  No Nmap port evidence for: {format_enriched_ports(missing)}")
    return lines


def nmap_warning_lines(stderr: str) -> list[str]:
    warnings = []
    for line in stderr.splitlines():
        if "Could not import all necessary Npcap functions" in line:
            warnings.append("Notice: Npcap functions unavailable; Nmap used TCP connect mode.")
        elif line.strip():
            warnings.append(f"Warning: {line.strip()}")
    return warnings


def format_nmap_deadline(timeout_seconds: float | None) -> str:
    return f"Deadline: {timeout_seconds:g}s/address" if timeout_seconds is not None else "Deadline: none"


def format_nmap_run(target: str, ports: Sequence[int], status: str,
                    elapsed_seconds: float | None) -> str:
    lines = [
        f"Target          : {target}",
        f"Ports scanned   : {format_enriched_ports(ports)}",
        f"Status          : {status}",
    ]
    if elapsed_seconds is not None:
        lines.append(f"Elapsed         : {elapsed_seconds:.2f}s")
    return "\n".join(lines)


def format_nmap_enrichment_skipped(
    reason: str,
    target: str = "unknown",
    ports: Sequence[int] = (),
    *,
    status: str = "skipped",
    elapsed_seconds: float | None = None,
    timeout_seconds: float | None = None,
    stderr: str = "",
) -> str:
    """Return a concise skipped or failed Nmap follow-up."""
    lines = ["Nmap service scan"]
    if timeout_seconds is not None:
        lines.append(format_nmap_deadline(timeout_seconds))
    lines.extend([format_nmap_run(target, ports, status, elapsed_seconds),
                  f"  Reason: {reason}"])
    lines.extend(nmap_warning_lines(stderr))
    return wrap_report(escape_controls("\n".join(lines), multiline=True))


def format_enriched_ports(ports: Sequence[int]) -> str:
    """Return a compact sorted port list for display."""
    sorted_ports = sorted(set(ports))
    if not sorted_ports:
        return "none"

    return ",".join(str(port) for port in sorted_ports)


def build_completed_nmap_enrichment(
    import_result: NmapXmlImport,
    target: str,
    ports: Sequence[int],
    *,
    elapsed_seconds: float | None = None,
    timeout_seconds: float | None = None,
) -> NmapEnrichmentResult:
    """Build a completed live Nmap enrichment result."""
    host = require_single_up_host(import_result)
    expected = ipaddress.ip_address(target)
    addresses = [ipaddress.ip_address(a.address) for a in host.addresses
                 if a.address_type in {"ipv4", "ipv6"}]
    if not any(address == expected or (
        address.version == 6 and not address.scope_id
        and address == ipaddress.ip_address(str(expected).split("%", 1)[0])
    ) for address in addresses):
        raise ValueError("Nmap returned evidence for a different target.")
    if any(p.port not in ports for p in host.tcp_ports or host.open_tcp_ports):
        raise ValueError("Nmap returned TCP ports outside the requested scope.")
    requested_ports = tuple(sorted(set(ports)))
    return NmapEnrichmentResult(
        status="completed" if import_result.metadata.finished_exit == "success" else "partial",
        target=target,
        ports_requested=requested_ports,
        terminal_text=format_nmap_enrichment_summary(
            import_result,
            target,
            requested_ports,
            elapsed_seconds=elapsed_seconds,
            timeout_seconds=timeout_seconds,
        ),
        import_result=import_result,
        execution=import_result.execution,
        elapsed_seconds=elapsed_seconds,
        timeout_seconds=timeout_seconds,
    )


def build_skipped_nmap_enrichment(
    reason: str,
    target: str,
    ports: Sequence[int],
) -> NmapEnrichmentResult:
    """Build a skipped live Nmap enrichment result."""
    return NmapEnrichmentResult(
        status="skipped",
        target=target,
        ports_requested=tuple(sorted(set(ports))),
        terminal_text=format_nmap_enrichment_skipped(reason, target, ports),
        reason=reason,
    )


def build_multi_nmap_enrichment(
    target: str,
    runs: Sequence[NmapEnrichmentResult],
) -> NmapEnrichmentResult:
    """Combine per-address Nmap runs without changing single-run output."""
    if len(runs) == 1:
        return runs[0]

    completed = sum(run.status == "completed" for run in runs)
    if any(run.status == "interrupted" for run in runs):
        status = "interrupted"
    elif completed == len(runs):
        status = "completed"
    elif completed:
        status = "partial"
    else:
        status = "partial" if any(run.import_result for run in runs) else "failed"
    lines = ["Nmap service scan"]
    if runs[0].timeout_seconds is not None:
        lines.append(format_nmap_deadline(runs[0].timeout_seconds))
    warnings = []
    for run in runs:
        lines.append("")
        lines.append(format_nmap_run(run.target, run.ports_requested, run.status, run.elapsed_seconds))
        if run.import_result is not None:
            lines.extend(nmap_evidence_lines(run.import_result, run.ports_requested))
        if run.reason:
            lines.append(f"  Reason: {run.reason}")
        for warning in nmap_warning_lines(run.execution.get("stderr", "")):
            if not warning.startswith("Notice:"):
                warning = f"{run.target}: {warning}"
            if warning not in warnings:
                warnings.append(warning)
    if warnings:
        lines.extend(warnings)
    return NmapEnrichmentResult(
        status=status,
        target=target,
        ports_requested=tuple(
            sorted({port for run in runs for port in run.ports_requested})
        ),
        terminal_text=wrap_report(escape_controls("\n".join(lines), multiline=True)),
        runs=tuple(runs),
        timeout_seconds=runs[0].timeout_seconds,
    )


def build_failed_nmap_enrichment(error, target, ports, *, elapsed_seconds=None, timeout_seconds=None):
    """Keep captured output; attach parsed partial evidence only after validation."""
    execution = getattr(error, "execution", {"status": "failed"})
    status = execution["status"]
    result = build_skipped_nmap_enrichment(str(error), target, ports)
    result = replace(result, status=status, execution=execution,
        elapsed_seconds=elapsed_seconds, timeout_seconds=timeout_seconds,
        terminal_text=format_nmap_enrichment_skipped(str(error), target, ports, status=status,
            elapsed_seconds=elapsed_seconds, timeout_seconds=timeout_seconds,
            stderr=execution.get("stderr", "")))
    if execution.get("stdout"):
        from modules.nmap_xml import parse_nmap_xml_text
        try:
            partial = build_completed_nmap_enrichment(parse_nmap_xml_text(execution["stdout"]), target, ports,
                elapsed_seconds=elapsed_seconds, timeout_seconds=timeout_seconds)
        except ValueError:
            pass  # Raw output remains available, but cannot establish endpoint evidence.
        else:
            result = replace(result, import_result=partial.import_result,
                terminal_text=format_nmap_enrichment_summary(
                    replace(partial.import_result, execution=execution), target, ports, status=status,
                    elapsed_seconds=elapsed_seconds, timeout_seconds=timeout_seconds
                ) + "\n" + wrap_report("  Reason: " + escape_controls(str(error))))
    return result
