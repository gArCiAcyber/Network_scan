"""TLS risk analysis helpers for scan evidence."""

import ipaddress
import math
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any


TLS_EXPIRY_SOON_DAYS = 30
SECONDS_PER_DAY = 86_400
LEGACY_TLS_PROTOCOLS = {
    "SSLV2": "high",
    "SSLV3": "high",
    "TLSV1": "medium",
    "TLSV1.0": "medium",
    "TLSV1.1": "medium",
}

DEFAULT_TLS_ANALYSIS = {
    "expired": None,
    "days_until_expiry": None,
    "expires_soon": None,
    "hostname_mismatch": None,
    "severity": "unknown",
    "reasons": [],
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
    protocol_severity: str | None = None,
) -> str:
    """Return a compact TLS risk severity label."""
    if expired is True or hostname_mismatch is True or protocol_severity == "high":
        return "high"

    if expires_soon is True or protocol_severity == "medium":
        return "medium"

    if expired is None and expires_soon is None and hostname_mismatch is None:
        return "unknown"

    return "low"


def build_tls_reason(
    reason_id: str,
    severity: str,
    title: str,
    evidence: str,
    impact: str,
    recommendation: str,
) -> dict[str, str]:
    """Build one deterministic TLS risk explanation reason."""
    return {
        "id": reason_id,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
    }


def build_default_tls_analysis(
    severity: str = "unknown",
    reasons: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Return a fresh default TLS analysis document."""
    analysis = DEFAULT_TLS_ANALYSIS.copy()
    analysis["severity"] = severity
    analysis["reasons"] = reasons or []
    return analysis


def normalize_tls_protocol(protocol: Any) -> str | None:
    """Normalize a TLS protocol value for risk comparison."""
    if not isinstance(protocol, str) or not protocol:
        return None

    return protocol.replace(" ", "").upper()


def get_tls_protocol_severity(tls_metadata: Mapping[str, Any]) -> str | None:
    """Return the legacy protocol severity when the handshake exposes one."""
    handshake = tls_metadata.get("handshake")

    if not isinstance(handshake, Mapping):
        return None

    normalized_protocol = normalize_tls_protocol(handshake.get("protocol"))

    if normalized_protocol is None:
        return None

    return LEGACY_TLS_PROTOCOLS.get(normalized_protocol)


def build_protocol_reason(tls_metadata: Mapping[str, Any]) -> dict[str, str] | None:
    """Build a reason when a weak or legacy TLS protocol was negotiated."""
    handshake = tls_metadata.get("handshake")

    if not isinstance(handshake, Mapping):
        return None

    protocol = handshake.get("protocol")
    protocol_severity = get_tls_protocol_severity(tls_metadata)

    if not isinstance(protocol, str) or protocol_severity is None:
        return None

    return build_tls_reason(
        reason_id="legacy_tls_protocol",
        severity=protocol_severity,
        title="Legacy TLS protocol negotiated",
        evidence=f"The TLS handshake negotiated {protocol}.",
        impact=(
            "Legacy TLS protocols may not meet modern transport security "
            "expectations."
        ),
        recommendation=(
            "Prefer TLSv1.2 or TLSv1.3 and disable legacy TLS/SSL protocols "
            "where operationally possible."
        ),
    )


def build_status_reasons(tls_metadata: Mapping[str, Any]) -> list[dict[str, str]]:
    """Build reasons for TLS collection status states."""
    status = tls_metadata.get("status")
    error = tls_metadata.get("error")

    if status == "failed":
        evidence = "TLS metadata collection failed."

        if isinstance(error, str) and error:
            evidence = f"{evidence} Error: {error}"

        return [
            build_tls_reason(
                reason_id="tls_metadata_collection_failed",
                severity="unknown",
                title="TLS metadata collection failed",
                evidence=evidence,
                impact=(
                    "Hylianscan could not confirm certificate or handshake "
                    "details for this service."
                ),
                recommendation=(
                    "Validate the service manually or retry with a stable "
                    "network path before making trust decisions."
                ),
            )
        ]

    if status == "no_certificate":
        return [
            build_tls_reason(
                reason_id="missing_certificate_metadata",
                severity="unknown",
                title="Missing certificate metadata",
                evidence="The TLS handshake completed but no peer certificate was returned.",
                impact=(
                    "Certificate identity, issuer, and expiry could not be "
                    "evaluated from the collected evidence."
                ),
                recommendation=(
                    "Confirm whether the service is expected to present a "
                    "certificate and review its TLS configuration."
                ),
            )
        ]

    return []


def build_certificate_reasons(
    expired: bool | None,
    expires_soon: bool | None,
    hostname_mismatch: bool | None,
    days_until_expiry: int | None,
    target_host: str,
) -> list[dict[str, str]]:
    """Build certificate-oriented TLS analysis reasons."""
    reasons: list[dict[str, str]] = []

    if expired is True:
        reasons.append(
            build_tls_reason(
                reason_id="certificate_expired",
                severity="high",
                title="Certificate expired",
                evidence=(
                    "The certificate expired "
                    f"{abs(days_until_expiry or 0)} days ago."
                ),
                impact=(
                    "Clients may reject the service or present trust warnings "
                    "because the certificate is no longer valid."
                ),
                recommendation="Renew or rotate the certificate.",
            )
        )
    elif expires_soon is True:
        reasons.append(
            build_tls_reason(
                reason_id="certificate_expires_soon",
                severity="medium",
                title="Certificate expires soon",
                evidence=f"The certificate expires in {days_until_expiry} days.",
                impact=(
                    "The service may become untrusted if the certificate is "
                    "not renewed before expiration."
                ),
                recommendation="Renew or rotate the certificate before expiration.",
            )
        )

    if hostname_mismatch is True:
        reasons.append(
            build_tls_reason(
                reason_id="hostname_mismatch",
                severity="medium",
                title="Certificate hostname mismatch",
                evidence=(
                    f"The certificate names do not match the target host "
                    f"{target_host}."
                ),
                impact=(
                    "Clients may reject the service or present trust warnings "
                    "because the certificate identity does not match the target."
                ),
                recommendation=(
                    "Serve a certificate whose DNS names or IP subject "
                    "alternative names match the intended target."
                ),
            )
        )

    return reasons


def build_tls_analysis(
    tls_metadata: Mapping[str, Any],
    target_host: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build actionable TLS risk indicators without modifying raw metadata."""
    if tls_metadata.get("status") != "collected":
        return build_default_tls_analysis(reasons=build_status_reasons(tls_metadata))

    certificate = tls_metadata.get("certificate")
    protocol_reason = build_protocol_reason(tls_metadata)
    protocol_severity = get_tls_protocol_severity(tls_metadata)

    if not isinstance(certificate, Mapping) or not certificate:
        reasons = build_status_reasons({"status": "no_certificate", "error": None})

        if protocol_reason is not None:
            reasons.insert(0, protocol_reason)

        return build_default_tls_analysis(
            severity=protocol_severity or "unknown",
            reasons=reasons,
        )

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
    severity = determine_tls_severity(
        expired,
        expires_soon,
        hostname_mismatch,
        protocol_severity,
    )
    reasons = [
        reason
        for reason in [
            protocol_reason,
            *build_certificate_reasons(
                expired=expired,
                expires_soon=expires_soon,
                hostname_mismatch=hostname_mismatch,
                days_until_expiry=days_until_expiry,
                target_host=target_host,
            ),
        ]
        if reason is not None
    ]

    return {
        "expired": expired,
        "days_until_expiry": days_until_expiry,
        "expires_soon": expires_soon,
        "hostname_mismatch": hostname_mismatch,
        "severity": severity,
        "reasons": reasons,
    }
