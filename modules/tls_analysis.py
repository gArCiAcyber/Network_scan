"""TLS risk analysis helpers for scan evidence."""

import ipaddress
import math
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any


TLS_EXPIRY_SOON_DAYS = 30
SECONDS_PER_DAY = 86_400

DEFAULT_TLS_ANALYSIS = {
    "expired": None,
    "days_until_expiry": None,
    "expires_soon": None,
    "hostname_mismatch": None,
    "severity": "unknown",
}


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
