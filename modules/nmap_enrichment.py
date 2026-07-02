"""Terminal formatting helpers for optional live Nmap enrichment."""

from __future__ import annotations

from collections.abc import Sequence

from modules.nmap_xml import NmapXmlImport, format_service_version, require_single_up_host


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
