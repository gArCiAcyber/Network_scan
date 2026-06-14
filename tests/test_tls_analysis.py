"""Tests for TLS certificate risk analysis."""

import unittest
from datetime import datetime, timezone

from modules.tls_analysis import (
    build_tls_analysis,
    detect_hostname_mismatch,
    dns_name_matches,
    parse_tls_datetime,
)


def build_tls_metadata(
    not_after: str,
    dns_names: list[str] | None = None,
    ip_addresses: list[str] | None = None,
    common_names: list[str] | None = None,
) -> dict[str, object]:
    """Build minimal collected TLS metadata for pure analysis tests."""
    certificate: dict[str, object] = {
        "not_after": not_after,
        "subject_alt_names": {
            "dns_names": dns_names or [],
            "ip_addresses": ip_addresses or [],
        },
        "subject": {
            "commonName": common_names or [],
        },
    }
    return {
        "status": "collected",
        "certificate": certificate,
    }


class TLSAnalysisTests(unittest.TestCase):
    """Validate pure TLS analysis behavior."""

    def test_parse_tls_datetime_accepts_openssl_expiry_format(self) -> None:
        parsed = parse_tls_datetime("Jun 15 12:00:00 2026 GMT")

        self.assertEqual(parsed, datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc))

    def test_expired_certificate_detection(self) -> None:
        metadata = build_tls_metadata(
            not_after="Jan 01 00:00:00 2026 GMT",
            dns_names=["example.com"],
        )

        analysis = build_tls_analysis(
            metadata,
            "example.com",
            now=datetime(2026, 1, 10, tzinfo=timezone.utc),
        )

        self.assertTrue(analysis["expired"])
        self.assertLess(analysis["days_until_expiry"], 0)
        self.assertFalse(analysis["expires_soon"])
        self.assertFalse(analysis["hostname_mismatch"])
        self.assertEqual(analysis["severity"], "high")

    def test_expires_soon_detection(self) -> None:
        metadata = build_tls_metadata(
            not_after="Jan 15 00:00:00 2026 GMT",
            dns_names=["example.com"],
        )

        analysis = build_tls_analysis(
            metadata,
            "example.com",
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

        self.assertFalse(analysis["expired"])
        self.assertEqual(analysis["days_until_expiry"], 14)
        self.assertTrue(analysis["expires_soon"])
        self.assertFalse(analysis["hostname_mismatch"])
        self.assertEqual(analysis["severity"], "medium")

    def test_hostname_mismatch_detection(self) -> None:
        metadata = build_tls_metadata(
            not_after="Dec 31 00:00:00 2026 GMT",
            dns_names=["other.example.com"],
        )

        analysis = build_tls_analysis(
            metadata,
            "example.com",
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

        self.assertFalse(analysis["expired"])
        self.assertTrue(analysis["hostname_mismatch"])
        self.assertEqual(analysis["severity"], "high")

    def test_hostname_mismatch_supports_ip_subject_alt_names(self) -> None:
        metadata = build_tls_metadata(
            not_after="Dec 31 00:00:00 2026 GMT",
            ip_addresses=["192.0.2.10"],
        )

        self.assertFalse(detect_hostname_mismatch(metadata, "192.0.2.10"))
        self.assertTrue(detect_hostname_mismatch(metadata, "192.0.2.11"))

    def test_wildcard_dns_matching(self) -> None:
        self.assertTrue(dns_name_matches("*.example.com", "www.example.com"))
        self.assertTrue(dns_name_matches("*.example.com.", "api.example.com."))
        self.assertFalse(dns_name_matches("*.example.com", "deep.api.example.com"))
        self.assertFalse(dns_name_matches("*.example.com", "example.com"))


if __name__ == "__main__":
    unittest.main()
