"""JSON export helpers for hylianscan scan results."""

import ipaddress
import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Protocol


HTTP_STATUS_PATTERN = re.compile(
    r"^HTTP/(?P<version>\S+)\s+"
    r"(?P<status_code>\d{3})"
    r"(?:\s+(?P<reason_phrase>.*?))?"
    r"(?=\s+[A-Za-z][A-Za-z0-9-]*:\s+|$)"
)
HTTP_HEADER_PATTERN = re.compile(r"(?<!\S)(?P<name>[A-Za-z][A-Za-z0-9-]*):\s+")
TLS_EXPIRY_SOON_DAYS = 30
SECONDS_PER_DAY = 86_400

DEFAULT_TLS_ANALYSIS = {
    "expired": None,
    "days_until_expiry": None,
    "expires_soon": None,
    "hostname_mismatch": None,
    "severity": "unknown",
}


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


def parse_tls_datetime(value: str | None) -> datetime | None:
    """Parse an OpenSSL certificate timestamp into a UTC datetime."""
    if not value:
        return None

    try:
        parsed_datetime = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None

    if parsed_datetime.tzinfo is None:
        return parsed_datetime.replace(tzinfo=timezone.utc)

    return parsed_datetime.astimezone(timezone.utc)


def calculate_days_until_expiry(expires_at: datetime, now: datetime) -> int:
    """Return whole calendar-ish days until certificate expiry."""
    total_seconds = (expires_at - now).total_seconds()

    if total_seconds >= 0:
        return math.ceil(total_seconds / SECONDS_PER_DAY)

    return math.floor(total_seconds / SECONDS_PER_DAY)


def is_ip_address(value: str) -> bool:
    """Return True when a target value is an IP address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False

    return True


def normalize_hostname(value: str) -> str:
    """Normalize a DNS hostname for certificate matching."""
    return value.strip().lower().rstrip(".")


def dns_name_matches(pattern: str, hostname: str) -> bool:
    """Return True when a certificate DNS name matches the target hostname."""
    normalized_pattern = normalize_hostname(pattern)
    normalized_hostname = normalize_hostname(hostname)

    if not normalized_pattern or not normalized_hostname:
        return False

    if not normalized_pattern.startswith("*."):
        return normalized_pattern == normalized_hostname

    pattern_labels = normalized_pattern.split(".")
    hostname_labels = normalized_hostname.split(".")

    return (
        len(pattern_labels) == len(hostname_labels)
        and pattern_labels[1:] == hostname_labels[1:]
    )


def get_certificate_common_names(certificate: Mapping[str, Any]) -> list[str]:
    """Return certificate subject common names."""
    subject = certificate.get("subject")

    if not isinstance(subject, Mapping):
        return []

    common_names = subject.get("commonName")

    if not isinstance(common_names, Sequence) or isinstance(common_names, str):
        return []

    return [str(common_name) for common_name in common_names if common_name]


def get_subject_alt_names(certificate: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the certificate subjectAltName structure."""
    subject_alt_names = certificate.get("subject_alt_names")

    if not isinstance(subject_alt_names, Mapping):
        return {}

    return subject_alt_names


def detect_hostname_mismatch(
    tls_metadata: Mapping[str, Any],
    target_host: str,
) -> bool | None:
    """Detect a TLS hostname mismatch when certificate names are available."""
    certificate = tls_metadata.get("certificate")

    if not isinstance(certificate, Mapping) or not certificate:
        return None

    subject_alt_names = get_subject_alt_names(certificate)
    normalized_target = normalize_hostname(target_host)

    if is_ip_address(normalized_target):
        ip_addresses = subject_alt_names.get("ip_addresses", [])

        if not isinstance(ip_addresses, Sequence) or isinstance(ip_addresses, str):
            return None

        normalized_ip_addresses = {
            str(ip_address).strip()
            for ip_address in ip_addresses
            if str(ip_address).strip()
        }
        return normalized_target not in normalized_ip_addresses

    dns_names = subject_alt_names.get("dns_names", [])

    if not isinstance(dns_names, Sequence) or isinstance(dns_names, str):
        dns_names = []

    certificate_names = [str(name) for name in dns_names if str(name).strip()]

    if not certificate_names:
        certificate_names = get_certificate_common_names(certificate)

    if not certificate_names:
        return None

    return not any(
        dns_name_matches(certificate_name, normalized_target)
        for certificate_name in certificate_names
    )


def determine_tls_severity(
    expired: bool | None,
    expires_soon: bool | None,
    hostname_mismatch: bool | None,
) -> str:
    """Return a compact TLS risk severity label."""
    if expired is True or hostname_mismatch is True:
        return "high"

    if expires_soon is True:
        return "medium"

    if expired is None and expires_soon is None and hostname_mismatch is None:
        return "unknown"

    return "low"


def build_tls_analysis(
    tls_metadata: Mapping[str, Any],
    target_host: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build actionable TLS risk indicators without modifying raw metadata."""
    if tls_metadata.get("status") != "collected":
        return DEFAULT_TLS_ANALYSIS.copy()

    certificate = tls_metadata.get("certificate")

    if not isinstance(certificate, Mapping) or not certificate:
        return DEFAULT_TLS_ANALYSIS.copy()

    now = now or datetime.now(timezone.utc)
    expires_at = parse_tls_datetime(certificate.get("not_after"))
    expired = None
    days_until_expiry = None
    expires_soon = None

    if expires_at is not None:
        days_until_expiry = calculate_days_until_expiry(expires_at, now)
        expired = expires_at <= now
        expires_soon = (
            not expired
            and days_until_expiry <= TLS_EXPIRY_SOON_DAYS
        )

    hostname_mismatch = detect_hostname_mismatch(tls_metadata, target_host)
    severity = determine_tls_severity(expired, expires_soon, hostname_mismatch)

    return {
        "expired": expired,
        "days_until_expiry": days_until_expiry,
        "expires_soon": expires_soon,
        "hostname_mismatch": hostname_mismatch,
        "severity": severity,
    }


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
