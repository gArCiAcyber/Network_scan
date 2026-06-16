"""Tests for final panel and saved TXT report rendering."""

import re
import unittest
from types import SimpleNamespace

from core.panel import build_final_panel, build_saved_text_report


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")

EXPIRED_TLS_METADATA = {
    "status": "collected",
    "handshake": {
        "protocol": "TLSv1.3",
    },
    "certificate": {
        "not_after": "Jan 01 00:00:00 2020 GMT",
        "subject": {
            "commonName": ["example.com"],
        },
        "issuer": {
            "organizationName": ["Example CA"],
        },
        "subject_alt_names": {
            "dns_names": ["example.com"],
            "ip_addresses": [],
        },
    },
    "error": None,
}


def strip_ansi(value: str) -> str:
    """Remove ANSI escape codes from captured terminal output."""
    return ANSI_PATTERN.sub("", value)


def make_tls_scan_result() -> SimpleNamespace:
    """Build a minimal scan result with TLS evidence."""
    return SimpleNamespace(
        target_host="example.com",
        resolved_ip="93.184.216.34",
        scanned_ports=1,
        open_ports=(
            SimpleNamespace(
                port=443,
                service="HTTPS",
                banner=None,
                response_time=0.01,
                web_url="https://example.com",
                tls=EXPIRED_TLS_METADATA,
            ),
        ),
        duration=1.23,
    )


class PanelRenderingTests(unittest.TestCase):
    """Validate terminal and saved TXT report rendering differences."""

    def test_final_panel_keeps_tls_risk_concise(self) -> None:
        report = strip_ansi(build_final_panel(make_tls_scan_result()))

        self.assertIn("tls-risk: high", report)
        self.assertNotIn("TLS Risk Explanations", report)
        self.assertNotIn("certificate_expired", report)
        self.assertNotIn("Certificate expired", report)

    def test_saved_text_report_adds_compact_tls_explanations(self) -> None:
        report = strip_ansi(build_saved_text_report(make_tls_scan_result()))

        self.assertIn("tls-risk: high", report)
        self.assertIn("TLS Risk Explanations", report)
        self.assertIn("443/tcp TLS risk reasons:", report)
        self.assertIn("certificate_expired [high]", report)
        self.assertIn("Recommendation: Renew or rotate the certificate.", report)


if __name__ == "__main__":
    unittest.main()
