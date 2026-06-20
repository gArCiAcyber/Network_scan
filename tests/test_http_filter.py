"""Tests for post-probe HTTP status-code filtering."""

import unittest

from modules.http_filter import (
    build_http_status_filter_metadata,
    filter_scan_result_by_http_status,
)
from modules.tcp_scanner import PortScanResult, ScanResult


def build_scan_result() -> ScanResult:
    """Build a mixed protocol result for report-filter tests."""
    return ScanResult(
        target_host="example.com",
        resolved_ip="93.184.216.34",
        scanned_ports=3,
        open_ports=(
            PortScanResult(
                port=80,
                service="HTTP",
                banner="HTTP/1.1 200 OK Server: example",
                response_time=0.01,
                web_url="http://93.184.216.34",
            ),
            PortScanResult(
                port=443,
                service="HTTPS",
                banner="HTTP/1.1 404 Not Found Server: example",
                response_time=0.02,
                web_url="https://93.184.216.34",
            ),
            PortScanResult(
                port=22,
                service="SSH",
                banner="SSH-2.0-OpenSSH_9.6",
                response_time=0.03,
            ),
        ),
        duration=0.5,
    )


class HTTPStatusFilterTests(unittest.TestCase):
    """Validate report-only HTTP status filtering."""

    def test_absent_match_codes_preserve_original_result(self) -> None:
        scan_result = build_scan_result()

        self.assertIs(
            filter_scan_result_by_http_status(scan_result, None),
            scan_result,
        )

    def test_filter_metadata_preserves_expression_and_resolved_codes(self) -> None:
        metadata = build_http_status_filter_metadata(
            "200,301-304",
            [304, 200, 301, 302, 303, 301],
        )

        self.assertEqual(
            metadata,
            {
                "http_status_codes": {
                    "expression": "200,301-304",
                    "resolved_codes": [200, 301, 302, 303, 304],
                }
            },
        )

    def test_filter_metadata_is_absent_without_match_code(self) -> None:
        self.assertIsNone(build_http_status_filter_metadata(None, None))

    def test_matching_http_status_is_reported(self) -> None:
        filtered_result = filter_scan_result_by_http_status(
            build_scan_result(),
            [200],
        )

        self.assertEqual(
            tuple(finding.port for finding in filtered_result.open_ports),
            (80,),
        )
        self.assertEqual(filtered_result.scanned_ports, 3)

    def test_non_matching_http_status_is_excluded(self) -> None:
        filtered_result = filter_scan_result_by_http_status(
            build_scan_result(),
            [301, 302],
        )

        self.assertEqual(filtered_result.open_ports, ())

    def test_non_http_finding_is_excluded_when_filter_is_active(self) -> None:
        filtered_result = filter_scan_result_by_http_status(
            build_scan_result(),
            [200, 404],
        )

        self.assertEqual(
            tuple(finding.port for finding in filtered_result.open_ports),
            (80, 443),
        )
        self.assertNotIn(22, (finding.port for finding in filtered_result.open_ports))


if __name__ == "__main__":
    unittest.main()
