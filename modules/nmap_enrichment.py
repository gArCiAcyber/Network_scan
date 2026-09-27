"""Terminal formatting helpers for optional live Nmap service scans."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
import ipaddress
from core.terminal import escape_controls

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


def format_nmap_enrichment_summary(
    import_result: NmapXmlImport,
    target: str,
    ports: Sequence[int],
) -> str:
    """Return a concise terminal summary for a live Nmap service scan."""
    host = require_single_up_host(import_result)
    lines = build_nmap_service_scan_header(
        target=target,
        ports=ports,
        status="completed" if import_result.metadata.finished_exit == "success" else "partial",
    )
    lines = [
        *lines,
        "",
        f"{'PORT':<10} {'STATE':<6} {'SERVICE':<9} VERSION",
    ]

    for port in host.tcp_ports or host.open_tcp_ports:
        service = port.service
        version = format_service_version(service)
        lines.append(
            f"{port.port}/tcp".ljust(10)
            + f" {port.state:<6}"
            + f" {service.name or 'unknown':<9}"
            + f" {version}"
        )

    if any(port.state != "open" for port in host.tcp_ports):
        lines.append("Nmap observed different states after native discovery; native evidence retained.")
    missing = sorted(set(ports) - {port.port for port in host.tcp_ports})
    if missing:
        lines.append(f"No per-port Nmap evidence for: {format_enriched_ports(missing)}")
    if import_result.execution.get("stderr"):
        lines.append(f"Warnings: {import_result.execution['stderr']}")
    lines.append(NMAP_SERVICE_SCAN_SEPARATOR)
    return escape_controls("\n".join(lines).rstrip(), multiline=True)


def format_nmap_enrichment_skipped(
    reason: str,
    target: str = "unknown",
    ports: Sequence[int] = (),
) -> str:
    """Return the standard skipped Nmap service scan block."""
    lines = build_nmap_service_scan_header(
        target=target,
        ports=ports,
        status="skipped",
    )
    lines.append(f"Reason          : {reason}")
    lines.append(NMAP_SERVICE_SCAN_SEPARATOR)
    return escape_controls("\n".join(lines), multiline=True)


def format_enriched_ports(ports: Sequence[int]) -> str:
    """Return a compact sorted port list for display."""
    sorted_ports = sorted(set(ports))
    if not sorted_ports:
        return "none"

    return ",".join(str(port) for port in sorted_ports)


NMAP_SERVICE_SCAN_SEPARATOR = "-" * 72


def build_nmap_service_scan_header(
    target: str,
    ports: Sequence[int],
    status: str,
) -> list[str]:
    """Build the standard Nmap Service Scan block header."""
    return [
        "[+] NMAP SERVICE SCAN",
        f"Target          : {target}",
        f"Ports scanned   : {format_enriched_ports(ports)}",
        f"Status          : {status}",
    ]


def build_completed_nmap_enrichment(
    import_result: NmapXmlImport,
    target: str,
    ports: Sequence[int],
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
        ),
        import_result=import_result,
        execution=import_result.execution,
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
    return NmapEnrichmentResult(
        status=status,
        target=target,
        ports_requested=tuple(
            sorted({port for run in runs for port in run.ports_requested})
        ),
        terminal_text="\n\n".join(run.terminal_text for run in runs),
        runs=tuple(runs),
    )


def build_failed_nmap_enrichment(error, target, ports):
    """Keep captured output; attach parsed partial evidence only after validation."""
    execution = getattr(error, "execution", {"status": "failed"})
    status = execution["status"]
    result = build_skipped_nmap_enrichment(str(error), target, ports)
    result = replace(result, status=status, execution=execution,
        terminal_text=result.terminal_text.replace("Status          : skipped", f"Status          : {status}"))
    if execution.get("stdout"):
        from modules.nmap_xml import parse_nmap_xml_text
        try:
            partial = build_completed_nmap_enrichment(parse_nmap_xml_text(execution["stdout"]), target, ports)
        except ValueError:
            pass  # Raw output remains available, but cannot establish endpoint evidence.
        else:
            result = replace(result, import_result=partial.import_result,
                terminal_text=result.terminal_text + "\n" + partial.terminal_text.replace(
                    "Status          : completed", "Status          : partial"))
    return result
