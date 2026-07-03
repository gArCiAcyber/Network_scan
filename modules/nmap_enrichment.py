"""Terminal formatting helpers for optional live Nmap service scans."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

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
        status="completed",
    )
    lines = [
        *lines,
        "",
        f"{'PORT':<10} {'STATE':<6} {'SERVICE':<9} VERSION",
    ]

    for port in host.open_tcp_ports:
        service = port.service
        version = format_service_version(service)
        lines.append(
            f"{port.port}/tcp".ljust(10)
            + f" {port.state:<6}"
            + f" {service.name or 'unknown':<9}"
            + f" {version}"
        )

    lines.append(NMAP_SERVICE_SCAN_SEPARATOR)
    return "\n".join(lines).rstrip()


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
    return "\n".join(lines)


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
        NMAP_SERVICE_SCAN_SEPARATOR,
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
    requested_ports = tuple(sorted(set(ports)))
    return NmapEnrichmentResult(
        status="completed",
        target=target,
        ports_requested=requested_ports,
        terminal_text=format_nmap_enrichment_summary(
            import_result,
            target,
            requested_ports,
        ),
        import_result=import_result,
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
