"""JSON export helpers for hylianscan scan results."""

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from modules.http_cookies import parse_http_cookies, parse_set_cookie_header
from modules.http_metadata import (
    get_first_header,
    parse_http_response_head,
)
from modules.http_security import build_http_security_observations
from modules.httpx_runner import HttpxResult
from modules.nmap_enrichment import NmapEnrichmentResult
from modules.nmap_xml import (
    NmapAddress,
    NmapPort,
    NmapXmlImport,
    require_single_up_host,
)
from modules.tcp_scanner import PortScanResult, ScanResult
from modules.target import ResolvedAddress, socket_family_for_address
from modules.tls_analysis import build_tls_analysis


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
        "cookies": [],
        "security": build_http_security_observations({}, url),
    }

    response_head = parse_http_response_head(banner)

    if response_head is None:
        return metadata

    headers = response_head.headers

    metadata.update(
        {
            "protocol": response_head.protocol,
            "status_code": response_head.status_code,
            "reason_phrase": response_head.reason_phrase,
            "server": get_first_header(headers, "server"),
            "location": get_first_header(headers, "location"),
            "content_type": get_first_header(headers, "content-type"),
            "headers": headers,
            "cookies": parse_http_cookies(headers),
            "security": build_http_security_observations(headers, url),
        }
    )

    return metadata


def build_probe_document(finding: PortScanResult) -> dict[str, Any]:
    """Build structured probe metadata for one open port."""
    probe = getattr(finding, "probe", None)

    if not isinstance(probe, Mapping):
        return {
            "name": "unknown",
            "transport_security": "unknown",
            "method": "passive_banner",
        }

    document = {
        "name": probe.get("name", "unknown"),
        "transport_security": probe.get("transport_security", "unknown"),
        "method": probe.get("method", "passive_banner"),
    }

    starttls = probe.get("starttls")
    if isinstance(starttls, Mapping):
        document["starttls"] = {
            "supported": bool(starttls.get("supported")),
            "attempted": bool(starttls.get("attempted")),
            "upgraded": bool(starttls.get("upgraded")),
            "error": starttls.get("error"),
        }

    return document


def build_port_document(
    finding: PortScanResult,
    target_host: str,
) -> dict[str, Any]:
    """Build one JSON-ready open-port document."""
    tls_metadata = finding.tls or {
        "status": "not_collected",
        "handshake": {},
        "certificate": {},
        "trust": {
            "verified": False,
            "reason": "Certificate chain trust was not evaluated.",
        },
        "error": None,
    }

    document = {
        "port": finding.port,
        "transport": "tcp",
        "status": "open",
        "service": {
            "name": finding.service,
        },
        "probe": build_probe_document(finding),
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

    address = getattr(finding, "address", None)
    if address:
        document["address"] = address
        document["address_family"] = getattr(finding, "address_family", None)

    return document


def _scan_addresses(scan_result: ScanResult) -> tuple[ResolvedAddress, ...]:
    """Return scan addresses, retaining compatibility with old result objects."""
    addresses = getattr(scan_result, "addresses", ())

    if addresses:
        return tuple(addresses)

    resolved_ips = getattr(scan_result, "resolved_ips", ()) or (
        scan_result.resolved_ip,
    )
    return tuple(
        ResolvedAddress(
            address=resolved_ip,
            family=socket_family_for_address(resolved_ip),
        )
        for resolved_ip in resolved_ips
    )


def _build_scan_address_document(address: ResolvedAddress) -> dict[str, Any]:
    """Build one resolved-address JSON document."""
    return {
        "address": address.address,
        "family": address.family_name,
        "reverse_dns": address.reverse_dns,
    }


def _scan_findings_by_family(
    scan_result: ScanResult,
) -> tuple[tuple[PortScanResult, ...], tuple[PortScanResult, ...]]:
    """Split findings without requiring legacy result fixtures to be upgraded."""
    ipv4 = getattr(scan_result, "ipv4_open_ports", None)
    ipv6 = getattr(scan_result, "ipv6_open_ports", None)

    if ipv4 is not None and ipv6 is not None:
        return tuple(ipv4), tuple(ipv6)

    return (
        tuple(
            finding
            for finding in scan_result.open_ports
            if getattr(finding, "address_family", None) != "ipv6"
        ),
        tuple(
            finding
            for finding in scan_result.open_ports
            if getattr(finding, "address_family", None) == "ipv6"
        ),
    )


def build_tcp_scan_document(
    scan_result: ScanResult,
    report_filters: Mapping[str, Any] | None = None,
    nmap_enrichment: NmapEnrichmentResult | None = None,
) -> dict[str, Any]:
    """Build a future-ready JSON document for TCP scan results."""
    addresses = _scan_addresses(scan_result)
    ipv4_addresses = tuple(
        address for address in addresses if address.family_name == "ipv4"
    )
    ipv6_addresses = tuple(
        address for address in addresses if address.family_name == "ipv6"
    )
    ipv4_open_ports, ipv6_open_ports = _scan_findings_by_family(scan_result)
    scan_document: dict[str, Any] = {
        "type": "tcp",
        "target": {
            "host": scan_result.target_host,
            "resolved_ip": scan_result.resolved_ip,
            "resolved_ips": [address.address for address in addresses],
            "address_family": getattr(scan_result, "address_family", "ipv4"),
            "addresses": {
                "ipv4": [
                    _build_scan_address_document(address)
                    for address in ipv4_addresses
                ],
                "ipv6": [
                    _build_scan_address_document(address)
                    for address in ipv6_addresses
                ],
            },
        },
        "scope": {
            "ports_tested": scan_result.scanned_ports,
        },
        "summary": {
            "open_ports": len(scan_result.open_ports),
            "ipv4_open_ports": len(ipv4_open_ports),
            "ipv6_open_ports": len(ipv6_open_ports),
        },
        "timing": {
            "duration_seconds": round(scan_result.duration, 6),
        },
    }

    if report_filters:
        scan_document["report_filters"] = dict(report_filters)

    open_ports = list(scan_result.open_ports)
    document = {
        "schema": {
            "name": "hylianscan_tcp_scan",
            "version": 1,
        },
        "scan": scan_document,
        "results": {
            "open_ports": [
                build_port_document(finding, scan_result.target_host)
                for finding in open_ports
            ],
            "ipv4": [
                build_port_document(finding, scan_result.target_host)
                for finding in ipv4_open_ports
            ],
            "ipv6": [
                build_port_document(finding, scan_result.target_host)
                for finding in ipv6_open_ports
            ],
        },
    }

    if nmap_enrichment is not None:
        document["enrichment"] = {
            "nmap": build_nmap_enrichment_document(nmap_enrichment)
        }

    return document


def write_tcp_json_report(
    scan_result: ScanResult,
    output_path: Path,
    report_filters: Mapping[str, Any] | None = None,
    nmap_enrichment: NmapEnrichmentResult | None = None,
) -> None:
    """Write TCP scan results as pretty JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    document = build_tcp_scan_document(
        scan_result,
        report_filters=report_filters,
        nmap_enrichment=nmap_enrichment,
    )
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
    httpx_result: HttpxResult | None = None,
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

    document = {
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

    if httpx_result is not None:
        httpx_document: dict[str, Any] = {
            "enabled": True,
            "status": httpx_result.status,
            "targets_requested": list(httpx_result.targets_requested),
            "live_services": len(httpx_result.findings),
        }
        if httpx_result.reason:
            httpx_document["reason"] = httpx_result.reason
        else:
            httpx_document["results"] = list(httpx_result.findings)
        document["enrichment"] = {"httpx": httpx_document}

    return document


def write_subdomain_json_report(
    target_domain: str,
    provider_results: Mapping[str, Sequence[str]],
    output_path: Path,
    httpx_result: HttpxResult | None = None,
) -> None:
    """Write passive subdomain discovery results as provider-aware JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    document = build_subdomain_discovery_document(
        target_domain,
        provider_results,
        httpx_result=httpx_result,
    )
    output_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def build_nmap_address_document(address: NmapAddress) -> dict[str, Any]:
    """Build one JSON-ready Nmap host address document."""
    return {
        "address": address.address,
        "type": address.address_type,
        "vendor": address.vendor,
    }


def build_nmap_port_document(port: NmapPort) -> dict[str, Any]:
    """Build one JSON-ready imported Nmap open TCP port document."""
    service = port.service

    return {
        "port": port.port,
        "protocol": port.protocol,
        "state": port.state,
        "service": {
            "name": service.name,
            "product": service.product,
            "version": service.version,
            "extrainfo": service.extrainfo,
            "tunnel": service.tunnel,
            "method": service.method,
            "conf": service.confidence_raw,
            "confidence": service.confidence,
            "cpe": list(service.cpes),
        },
    }


def build_nmap_enrichment_document(
    enrichment: NmapEnrichmentResult,
) -> dict[str, Any]:
    """Build the optional live Nmap enrichment JSON section."""
    document: dict[str, Any] = {
        "enabled": True,
        "status": enrichment.status,
        "target": enrichment.target,
        "ports_requested": list(enrichment.ports_requested),
    }

    if enrichment.status == "skipped":
        document["reason"] = enrichment.reason or "unknown"
        return document

    if enrichment.import_result is None:
        document["status"] = "skipped"
        document["reason"] = "Nmap Service Scan did not return import data."
        return document

    host = require_single_up_host(enrichment.import_result)
    document["ports_returned"] = [
        port.port for port in host.open_tcp_ports
    ]
    document["results"] = [
        build_nmap_port_document(port) for port in host.open_tcp_ports
    ]

    return document


def build_nmap_xml_import_document(
    import_result: NmapXmlImport,
    source_path: str,
) -> dict[str, Any]:
    """Build a JSON document for imported Nmap XML evidence."""
    host = require_single_up_host(import_result)
    metadata = import_result.metadata

    return {
        "tool": "hylianscan",
        "mode": "nmap_xml_import",
        "source": {
            "path": source_path,
            "scanner": metadata.scanner,
            "args": metadata.args,
            "version": metadata.version,
            "xmloutputversion": metadata.xmloutputversion,
            "start": metadata.start,
            "startstr": metadata.startstr,
        },
        "host": {
            "status": host.status,
            "addresses": [
                build_nmap_address_document(address) for address in host.addresses
            ],
            "primary_address": host.primary_address,
        },
        "open_tcp_ports": [
            build_nmap_port_document(port) for port in host.open_tcp_ports
        ],
    }


def write_nmap_xml_import_json_report(
    import_result: NmapXmlImport,
    source_path: str,
    output_path: Path,
) -> None:
    """Write imported Nmap XML evidence as pretty JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    document = build_nmap_xml_import_document(import_result, source_path)
    output_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
