"""JSON export helpers for hylianscan scan results."""

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from modules.tls_analysis import build_tls_analysis


HTTP_STATUS_PATTERN = re.compile(
    r"^HTTP/(?P<version>\S+)\s+"
    r"(?P<status_code>\d{3})"
    r"(?:\s+(?P<reason_phrase>.*?))?"
    r"(?=\s+[A-Za-z][A-Za-z0-9-]*:\s+|$)"
)
HTTP_HEADER_PATTERN = re.compile(r"(?<!\S)(?P<name>[A-Za-z][A-Za-z0-9-]*):\s+")


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


def append_header(headers: dict[str, list[str]], name: str, value: str) -> None:
    """Append one normalized HTTP header value."""
    header_name = name.lower()
    header_value = " ".join(value.split())

    if not header_value:
        return

    headers.setdefault(header_name, []).append(header_value)


def parse_http_headers(header_block: str) -> dict[str, list[str]]:
    """Parse compact HTTP headers into a case-normalized mapping."""
    headers: dict[str, list[str]] = {}
    matches = list(HTTP_HEADER_PATTERN.finditer(header_block))

    for index, match in enumerate(matches):
        value_start = match.end()
        value_end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(header_block)
        )
        append_header(
            headers=headers,
            name=match.group("name"),
            value=header_block[value_start:value_end],
        )

    return headers


def get_first_header(headers: Mapping[str, Sequence[str]], name: str) -> str | None:
    """Return the first value for a normalized HTTP header name."""
    values = headers.get(name)

    if not values:
        return None

    return values[0]


def parse_http_metadata(banner: str | None, url: str | None) -> dict[str, Any]:
    """Parse HTTP response metadata while preserving the raw banner elsewhere."""
    metadata: dict[str, Any] = {
        "url": url,
        "protocol": None,
        "status_code": None,
        "reason_phrase": None,
        "server": None,
        "location": None,
        "content_type": None,
        "headers": {},
    }

    if banner is None:
        return metadata

    status_match = HTTP_STATUS_PATTERN.match(banner)

    if status_match is None:
        return metadata

    protocol = f"HTTP/{status_match.group('version')}"
    status_code = int(status_match.group("status_code"))
    reason_phrase = (
        " ".join((status_match.group("reason_phrase") or "").split())
        or None
    )
    headers = parse_http_headers(banner[status_match.end():])

    metadata.update(
        {
            "protocol": protocol,
            "status_code": status_code,
            "reason_phrase": reason_phrase,
            "server": get_first_header(headers, "server"),
            "location": get_first_header(headers, "location"),
            "content_type": get_first_header(headers, "content-type"),
            "headers": headers,
        }
    )

    return metadata


def build_port_document(
    finding: PortFindingExportView,
    target_host: str,
) -> dict[str, Any]:
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
        "http": parse_http_metadata(finding.banner, finding.web_url),
        "tls": tls_metadata,
        "tls_analysis": build_tls_analysis(tls_metadata, target_host),
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
                build_port_document(finding, scan_result.target_host)
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
