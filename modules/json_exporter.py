"""JSON export helpers for hylianscan scan results."""

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol


class PortFindingExportView(Protocol):
    """Minimum fields required to export an open TCP port."""

    port: int
    service: str
    banner: str | None
    response_time: float
    web_url: str | None
    tls: dict[str, Any] | None


class ScanResultExportView(Protocol):
    """Minimum fields required to export a TCP scan summary."""

    target_host: str
    resolved_ip: str
    scanned_ports: int
    open_ports: Sequence[PortFindingExportView]
    duration: float


def build_port_document(finding: PortFindingExportView) -> dict[str, Any]:
    """Build one JSON-ready open-port document."""
    tls_metadata = finding.tls or {
        "status": "not_collected",
        "handshake": {},
        "certificate": {},
        "error": None,
    }

    return {
        "port": finding.port,
        "transport": "tcp",
        "status": "open",
        "service": {
            "name": finding.service,
        },
        "banner": {
            "raw": finding.banner,
        },
        "http": {
            "url": finding.web_url,
        },
        "tls": tls_metadata,
        "timing": {
            "response_time_seconds": round(finding.response_time, 6),
        },
    }


def build_tcp_scan_document(scan_result: ScanResultExportView) -> dict[str, Any]:
    """Build a future-ready JSON document for TCP scan results."""
    return {
        "schema": {
            "name": "hylianscan_tcp_scan",
            "version": 1,
        },
        "scan": {
            "type": "tcp",
            "target": {
                "host": scan_result.target_host,
                "resolved_ip": scan_result.resolved_ip,
            },
            "scope": {
                "ports_tested": scan_result.scanned_ports,
            },
            "summary": {
                "open_ports": len(scan_result.open_ports),
            },
            "timing": {
                "duration_seconds": round(scan_result.duration, 6),
            },
        },
        "results": {
            "open_ports": [
                build_port_document(finding)
                for finding in scan_result.open_ports
            ],
        },
    }


def write_tcp_json_report(scan_result: ScanResultExportView, output_path: Path) -> None:
    """Write TCP scan results as pretty JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    document = build_tcp_scan_document(scan_result)
    output_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def normalize_subdomain_results(subdomains: Sequence[str]) -> list[str]:
    """Normalize, deduplicate, and sort subdomain results for export."""
    normalized = {
        subdomain.strip().lower().strip(".")
        for subdomain in subdomains
        if subdomain.strip()
    }
    return sorted(normalized)


def build_subdomain_provider_documents(
    provider_results: Mapping[str, Sequence[str]],
) -> list[dict[str, Any]]:
    """Build provider-specific subdomain result documents."""
    provider_documents: list[dict[str, Any]] = []

    for provider_name in sorted(provider_results):
        subdomains = normalize_subdomain_results(provider_results[provider_name])
        provider_documents.append(
            {
                "name": provider_name,
                "count": len(subdomains),
                "subdomains": subdomains,
            }
        )

    return provider_documents


def build_subdomain_discovery_document(
    target_domain: str,
    provider_results: Mapping[str, Sequence[str]],
) -> dict[str, Any]:
    """Build a provider-aware JSON document for passive subdomain discovery."""
    provider_documents = build_subdomain_provider_documents(provider_results)
    subdomain_sources: dict[str, list[str]] = {}

    for provider_document in provider_documents:
        provider_name = provider_document["name"]

        for subdomain in provider_document["subdomains"]:
            subdomain_sources.setdefault(subdomain, []).append(provider_name)

    final_subdomains = sorted(
        {
            subdomain
            for provider_document in provider_documents
            for subdomain in provider_document["subdomains"]
        }
    )

    return {
        "schema": {
            "name": "hylianscan_passive_subdomain_discovery",
            "version": 1,
        },
        "discovery": {
            "type": "passive_subdomain",
            "target": {
                "domain": target_domain,
            },
            "summary": {
                "providers": len(provider_documents),
                "deduplicated_subdomains": len(final_subdomains),
            },
        },
        "providers": provider_documents,
        "results": {
            "subdomains": final_subdomains,
            "sources": subdomain_sources,
        },
    }


def write_subdomain_json_report(
    target_domain: str,
    provider_results: Mapping[str, Sequence[str]],
    output_path: Path,
) -> None:
    """Write passive subdomain discovery results as provider-aware JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    document = build_subdomain_discovery_document(target_domain, provider_results)
    output_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
