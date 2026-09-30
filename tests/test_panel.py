"""Tests for final panel and saved TXT report rendering."""

import re
import socket
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from core.panel import build_final_panel, build_nmap_panel, build_quiet_final_panel, build_saved_text_report, get_triforce_symbol
from core.banner import build_banner
from core.colors import GREEN, RESET
from modules.json_exporter import build_tcp_scan_document
from modules.target import ResolvedAddress
from modules.tcp_scanner import PortScanResult, ScanResult


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


def make_http_scan_result() -> SimpleNamespace:
    """Build a minimal scan result with compact HTTP evidence."""
    return SimpleNamespace(
        target_host="example.com",
        resolved_ip="93.184.216.34",
        scanned_ports=1,
        open_ports=(
            SimpleNamespace(
                port=80,
                service="HTTP",
                banner=(
                    "HTTP/1.1 301 Moved Permanently\r\n"
                    "Server: cloudflare\r\n"
                    "Location: https://example.com/\r\n"
                    "Content-Type: text/html\r\n\r\n"
                ),
                response_time=0.01,
                web_url="http://example.com",
                tls=None,
            ),
        ),
        duration=1.23,
    )


class PanelRenderingTests(unittest.TestCase):
    """Validate terminal and saved TXT report rendering differences."""

    def test_tls_is_only_in_json_and_rendering_preserves_evidence(self) -> None:
        result = make_tls_scan_result()
        before = build_tcp_scan_document(result)
        for render in (build_final_panel, build_quiet_final_panel, build_saved_text_report):
            with self.subTest(renderer=render.__name__):
                report = strip_ansi(render(result))
                for detail in ("tls-risk", "tls-trust", "TLS Risk", "TLSv1.3", "Example CA", "certificate_expired"):
                    self.assertNotIn(detail, report)
                self.assertIn("Open 93.184.216.34:443", report)
        self.assertEqual(before, build_tcp_scan_document(result))
        port = before["results"]["open_ports"][0]
        self.assertEqual(port["tls"], EXPIRED_TLS_METADATA)
        self.assertEqual(port["tls_analysis"]["severity"], "high")

    def test_saved_text_report_records_active_http_status_filter(self) -> None:
        report = strip_ansi(
            build_saved_text_report(
                make_http_scan_result(),
                match_code_expression="200,301-304",
            )
        )

        self.assertIn(
            "HTTP filter: 200,301-304 (report only)",
            report,
        )

    def test_saved_text_report_omits_inactive_http_status_filter(self) -> None:
        report = strip_ansi(build_saved_text_report(make_http_scan_result()))

        self.assertNotIn("Report Filter:", report)

    def test_http_details_stay_out_of_compact_report(self) -> None:
        report = strip_ansi(build_final_panel(make_http_scan_result()))

        self.assertIn("Open 93.184.216.34:80", report)
        self.assertNotIn("301 Moved Permanently", report)
        self.assertNotIn("http-server-header", report)

    def test_final_panel_has_one_discreet_brand_mark(self) -> None:
        report = strip_ansi(build_final_panel(make_http_scan_result()))

        self.assertIn(f"[ SCAN BY THE TRIFORCE {get_triforce_symbol()} ]", report)
        self.assertEqual(report.count("TRIFORCE"), 1)

    def test_separators_frame_native_results_and_nmap_in_normal_output_only(self) -> None:
        for width in (40, 100):
            with self.subTest(width=width), patch(
                "core.terminal.shutil.get_terminal_size", return_value=SimpleNamespace(columns=width),
            ):
                separator = "-" * min(72, width)
                native = strip_ansi(build_final_panel(make_http_scan_result()))
                self.assertEqual(native.splitlines().count(separator), 3)
                self.assertTrue(native.rstrip().endswith(separator))
                nmap_text = ("Nmap service scan\nTarget          : 192.0.2.10\nStatus          : completed"
                             "\n\nPORT       STATE  SERVICE   VERSION\n80/tcp     open   http      nginx")
                colored_nmap = build_nmap_panel(nmap_text)
                nmap = strip_ansi(colored_nmap)
                self.assertEqual(colored_nmap.split(RESET, 1)[0], GREEN + nmap.rsplit("\n", 1)[0])
                self.assertIn("[+] NMAP SERVICE SCAN", nmap)
                self.assertTrue(nmap.endswith(separator))
                self.assertTrue(all(len(line) <= width for line in (native + "\n" + nmap).splitlines()))
                self.assertEqual(build_nmap_panel(nmap_text, quiet=True), nmap_text)
                self.assertNotIn(separator, build_quiet_final_panel(make_http_scan_result()))

    def test_final_panel_does_not_claim_an_unproven_host_status(self) -> None:
        scan_result = make_http_scan_result()
        scan_result.open_ports = ()

        report = strip_ansi(build_final_panel(scan_result))

        self.assertNotIn("Host is up.", report)

    def test_filtered_empty_result_reports_hidden_open_port_findings(self) -> None:
        scan_result = make_http_scan_result()
        scan_result.open_ports = ()

        report = strip_ansi(
            build_final_panel(
                scan_result,
                native_open_port_count=3,
                http_status_filter="302",
            )
        )

        self.assertIn("Results: 3 open", report)
        self.assertIn("0 shown, 3 hidden", report)
        self.assertIn(
            "No open findings matched the HTTP filter.",
            report,
        )
        self.assertNotIn("No open ports found", report)

    def test_multiple_ipv4_findings_identify_their_addresses(self) -> None:
        scan_result = ScanResult(
            target_host="example.com",
            resolved_ip="192.0.2.10",
            scanned_ports=1,
            open_ports=(
                PortScanResult(
                    80,
                    "HTTP",
                    None,
                    0.01,
                    address="192.0.2.10",
                    address_family="ipv4",
                ),
                PortScanResult(
                    80,
                    "HTTP",
                    None,
                    0.02,
                    address="192.0.2.11",
                    address_family="ipv4",
                ),
            ),
            duration=0.02,
            resolved_ips=("192.0.2.10", "192.0.2.11"),
            address_family="dual-stack",
            addresses=(
                ResolvedAddress("192.0.2.10", socket.AF_INET),
                ResolvedAddress("192.0.2.11", socket.AF_INET),
            ),
        )

        report = strip_ansi(build_final_panel(scan_result))

        self.assertIn("Open 192.0.2.10:80", report)
        self.assertIn("Open 192.0.2.11:80", report)

    def test_finished_attempts_do_not_mean_all_port_states_are_known(self) -> None:
        result = ScanResult(
            "example.com", "192.0.2.10", 65535,
            (PortScanResult(80, "HTTP", "HTTP/1.1 301 Moved\r\nLocation: https://example.com/\r\n\r\n", .01,
                            address="192.0.2.10"),
             PortScanResult(443, "HTTPS", None, .01, address="192.0.2.10")),
            266.93, resolved_ips=("192.0.2.10", "192.0.2.11"),
            status="partial", completed_attempts=131070,
            outcomes={"open": 2, "timeout": 131068},
        )
        for render in (build_final_panel, build_quiet_final_panel, build_saved_text_report):
            with self.subTest(renderer=render.__name__):
                report = strip_ansi(render(result))
                self.assertIn("Attempts: 131,070/131,070 finished", report)
                self.assertIn("131,068 unknown (connection timeout)", report)
                self.assertNotIn("Missing outcomes:", report)
                self.assertIn("Open 192.0.2.10:80", report)
                self.assertIn("192.0.2.11: no open TCP ports observed", report)
                self.assertNotIn("PORT       STATE", report)

    def test_interruption_and_unfinished_coverage_are_independent(self) -> None:
        result = ScanResult("localhost", "127.0.0.1", 2, (), .1,
                            status="interrupted", completed_attempts=1, outcomes={"timeout": 1})
        report = build_quiet_final_panel(result)
        self.assertIn("Attempts: 1/2 finished (interrupted)", report)
        self.assertIn("Missing outcomes: 1 attempt", report)
        report = build_quiet_final_panel(replace(result, completed_attempts=2, outcomes={"timeout": 2}))
        self.assertIn("Attempts: 2/2 finished (interrupted)", report)
        self.assertNotIn("Missing outcomes:", report)

    def test_unknown_and_refused_outcomes_and_skipped_scan(self) -> None:
        result = ScanResult("localhost", "127.0.0.1", 4, (), .1,
                            status="partial", completed_attempts=4,
                            outcomes={"timeout": 1, "refused": 1, "unreachable": 1, "error": 1})
        report = build_quiet_final_panel(result)
        self.assertIn("1 refused", report)
        self.assertIn("1 unknown (unreachable)", report)
        self.assertRegex(report, r"1 unknown\s+\(connection error\)")
        self.assertIn("No open ports observed.", report)
        self.assertNotIn("closed", report)
        self.assertNotIn("filtered", report)
        report = build_quiet_final_panel(replace(result, status="unconfirmed", completed_attempts=0, outcomes={}))
        self.assertIn("Attempts: 0/0 finished (host discovery unconfirmed)", report)
        self.assertIn("TCP scan skipped", report)

    def test_probe_failures_preserve_open_state_and_incomplete_response(self) -> None:
        for status in ("failed", "incomplete", "cancelled", "disabled", "unavailable"):
            result = make_http_scan_result()
            result.open_ports[0].probe = {"status": status, "error": "TLS secret diagnostic"}
            report = build_quiet_final_panel(result)
            self.assertIn("Open 93.184.216.34:80", report)
            self.assertNotIn("TLS secret diagnostic", report)
            result.open_ports[0].banner = None
            self.assertIn("Open 93.184.216.34:80", build_quiet_final_panel(result))

    def test_narrow_terminal_wraps_compact_report(self) -> None:
        result = make_http_scan_result()
        url = "https://example.com/" + "a" * 120
        result.open_ports[0].banner = f"HTTP/1.1 301 Moved\r\nLocation: {url}\r\n\r\n"
        with patch("core.terminal.shutil.get_terminal_size", return_value=SimpleNamespace(columns=40)):
            report = strip_ansi(build_final_panel(result))
        self.assertTrue(all(len(line) <= 40 for line in report.splitlines()))
        self.assertIn("Open 93.184.216.34:80", report)
        self.assertNotIn(url, report)

    def test_narrow_startup_banner_retains_identity_without_wide_art(self) -> None:
        with patch("core.banner.shutil.get_terminal_size", return_value=SimpleNamespace(columns=32)):
            banner = strip_ansi(build_banner())
        self.assertIn("HYLIANSCAN", banner)
        self.assertTrue(all(len(line) <= 32 for line in banner.splitlines()))

    def test_banner_stays_in_json(self) -> None:
        banner = "SSH-2.0-example\r\n" + "additional evidence " * 100
        result = ScanResult("localhost", "127.0.0.1", 1,
                            (PortScanResult(22, "SSH", banner, .1),), .1)
        report = build_quiet_final_panel(result)
        self.assertIn("Open 127.0.0.1:22", report)
        self.assertNotIn("SSH-2.0-example", report)
        self.assertNotIn("additional evidence", report)
        self.assertEqual(build_tcp_scan_document(result)["results"]["open_ports"][0]["banner"]["raw"], banner)

    def test_scoped_ipv6_and_missing_address_do_not_merge_findings(self) -> None:
        result = ScanResult("localhost", "fe80::1", 1,
            (PortScanResult(22, "SSH", None, .1, address="fe80::1", scope_id=3),
             PortScanResult(22, "SSH", None, .1, address="fe80::1", scope_id=4),
             PortScanResult(22, "SSH", None, .1)), .1,
            addresses=(ResolvedAddress("fe80::1", socket.AF_INET6, scope_id=3),
                       ResolvedAddress("fe80::1", socket.AF_INET6, scope_id=4)))
        report = build_quiet_final_panel(result)
        for endpoint in ("Open [fe80::1%3]:22", "Open [fe80::1%4]:22", "Open ?:22"):
            self.assertIn(endpoint, report)

    def test_txt_keeps_identity_without_raw_dictionary_or_port_list_dump(self) -> None:
        result = ScanResult("localhost", "127.0.0.1", 65535, (), .1,
                            run_id="test-run", started_at="start", finished_at="finish",
                            requested_ports=tuple(range(1, 65536)))
        report = build_saved_text_report(result)
        self.assertIn("Run ID: test-run", report)
        self.assertIn("Started: start", report)
        self.assertNotIn("Requested ports:", report)
        self.assertNotIn("{}", report)


if __name__ == "__main__":
    unittest.main()
