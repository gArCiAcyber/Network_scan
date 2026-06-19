"""JSON export helpers for hylianscan scan results."""

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from modules.http_metadata import (
    get_first_header,
    parse_http_headers,
    parse_http_response_head,
)
from modules.tls_analysis import build_tls_analysis


HTTP_SECURITY_HEADERS = (
    (
        "strict-transport-security",
        "Strict-Transport-Security",
        "missing_strict_transport_security",
        True,
    ),
    (
        "content-security-policy",
        "Content-Security-Policy",
        "missing_content_security_policy",
        False,
    ),
    (
        "x-frame-options",
        "X-Frame-Options",
        "missing_x_frame_options",
        False,
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options",
        "missing_x_content_type_options",
        False,
    ),
    (
        "referrer-policy",
        "Referrer-Policy",
        "missing_referrer_policy",
        False,
    ),
    (
        "permissions-policy",
        "Permissions-Policy",
        "missing_permissions_policy",
        False,
    ),
    (
        "cross-origin-opener-policy",
        "Cross-Origin-Opener-Policy",
        "missing_cross_origin_opener_policy",
        False,
    ),
)


class PortFindingExportView(Protocol):
    """Minimum fields required to export an open TCP port."""

    port: int
    service: str
    banner: str | None
    response_time: float
    web_url: str | None
    tls: dict[str, Any] | None
    probe: dict[str, Any] | None


class ScanResultExportView(Protocol):
    """Minimum fields required to export a TCP scan summary."""

    target_host: str
    resolved_ip: str
    scanned_ports: int
    open_ports: Sequence[PortFindingExportView]
    duration: float


def parse_cookie_attributes(attribute_parts: Sequence[str]) -> dict[str, str | bool]:
    """Parse Set-Cookie attribute parts into a normalized mapping."""
    attributes: dict[str, str | bool] = {}

    for attribute_part in attribute_parts:
        attribute = attribute_part.strip()

        if not attribute:
            continue

        if "=" in attribute:
            name, value = attribute.split("=", maxsplit=1)
            attributes[name.strip().lower()] = value.strip()
        else:
            attributes[attribute.lower()] = True

    return attributes


def build_cookie_security_observations(
    name: str,
    secure: bool,
    httponly: bool,
    samesite: str | None,
    path: str | None,
    domain: str | None,
) -> list[str]:
    """Build simple cookie security observations."""
    observations: list[str] = []

    if not secure:
        observations.append("missing_secure")

    if not httponly:
        observations.append("missing_httponly")

    if samesite is None:
        observations.append("missing_samesite")

    if name.startswith("__Host-") and secure and path == "/" and domain is None:
        observations.append("host_prefix_valid")

    if name.startswith("__Secure-") and secure:
        observations.append("secure_prefix_valid")

    return observations


def parse_set_cookie_header(header_value: str) -> dict[str, Any] | None:
    """Parse one Set-Cookie header into structured metadata."""
    parts = [part.strip() for part in header_value.split(";")]

    if not parts or not parts[0]:
        return None

    name_value = parts[0]
    if "=" in name_value:
        name, value = name_value.split("=", maxsplit=1)
        cookie_name = name.strip()
        value_present = bool(value)
    else:
        cookie_name = name_value.strip()
        value_present = False

    if not cookie_name:
        return None

    attributes = parse_cookie_attributes(parts[1:])
    secure = bool(attributes.get("secure"))
    httponly = bool(attributes.get("httponly"))
    samesite = attributes.get("samesite")
    path = attributes.get("path")
    domain = attributes.get("domain")
    expires = attributes.get("expires")
    max_age = attributes.get("max-age")

    return {
        "name": cookie_name,
        "value_present": value_present,
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite if isinstance(samesite, str) else None,
        "path": path if isinstance(path, str) else None,
        "domain": domain if isinstance(domain, str) else None,
        "expires": expires if isinstance(expires, str) else None,
        "max_age": max_age if isinstance(max_age, str) else None,
        "uses_host_prefix": cookie_name.startswith("__Host-"),
        "uses_secure_prefix": cookie_name.startswith("__Secure-"),
        "security_observations": build_cookie_security_observations(
            name=cookie_name,
            secure=secure,
            httponly=httponly,
            samesite=samesite if isinstance(samesite, str) else None,
            path=path if isinstance(path, str) else None,
            domain=domain if isinstance(domain, str) else None,
        ),
    }


def parse_http_cookies(headers: Mapping[str, Sequence[str]]) -> list[dict[str, Any]]:
    """Parse Set-Cookie headers into structured cookie metadata."""
    cookies: list[dict[str, Any]] = []

    for header_value in headers.get("set-cookie", []):
        cookie = parse_set_cookie_header(header_value)

        if cookie is not None:
            cookies.append(cookie)

    return cookies


def is_https_url(url: str | None) -> bool:
    """Return True when the collected URL clearly uses HTTPS."""
    return bool(url and url.lower().startswith("https://"))


def build_http_security_observations(
    headers: Mapping[str, Sequence[str]],
    url: str | None,
) -> dict[str, Any]:
    """Build factual HTTP security-header observations from collected headers."""
    https_response = is_https_url(url)
    header_documents: dict[str, dict[str, Any]] = {}
    present_headers: list[str] = []
    missing_headers: list[str] = []
    observations: list[str] = []

    for header_key, header_name, missing_observation, https_only in HTTP_SECURITY_HEADERS:
        values = list(headers.get(header_key, []))
        present = bool(values)
        expected = not https_only or https_response
        header_observations: list[str] = []

        if present:
            present_headers.append(header_key)
        elif expected:
            missing_headers.append(header_key)
            header_observations.append(missing_observation)
            observations.append(missing_observation)
        elif https_only:
            header_observations.append("not_expected_on_plain_http")

        header_documents[header_key] = {
            "name": header_name,
            "present": present,
            "expected": expected,
            "values": values,
            "observations": header_observations,
        }

    return {
        "headers": header_documents,
        "present": present_headers,
        "missing": missing_headers,
        "observations": observations,
    }


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


def build_probe_document(finding: PortFindingExportView) -> dict[str, Any]:
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
