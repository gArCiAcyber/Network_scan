"""Terminal formatting helpers for optional live Nmap enrichment."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from modules.nmap_xml import NmapXmlImport, format_service_version, require_single_up_host


@dataclass(frozen=True)
class NmapEnrichmentResult:
    """Structured result for optional live Nmap enrichment."""

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
    """Return a concise terminal summary for live Nmap enrichment."""
    host = require_single_up_host(import_result)
    lines = [
        "Nmap Enrichment",
        "Status: completed",
        f"Target: {target}",
        f"Ports enriched: {format_enriched_ports(ports)}",
        "",
    ]

    for port in host.open_tcp_ports:
        service = port.service
        lines.append(
            f"{port.port}/tcp".ljust(8)
            + " "
            + f"{service.name or 'unknown':<8}"
            + " "
            + f"{format_service_version(service):<24}"
            + " "
            + f"method={service.method or 'unknown'} "
            + f"confidence={service.confidence}"
        )

    return "\n".join(lines).rstrip()


def format_nmap_enrichment_skipped(reason: str) -> str:
    """Return the standard skipped enrichment message."""
    return f"Nmap enrichment skipped: {reason}"


def format_enriched_ports(ports: Sequence[int]) -> str:
    """Return a compact sorted port list for display."""
    return ",".join(str(port) for port in sorted(set(ports)))


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
        terminal_text=format_nmap_enrichment_skipped(reason),
        reason=reason,
    )
