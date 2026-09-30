"""Tests for TCP scanner orchestration helpers."""

import io
import os
import socket
import unittest
from unittest.mock import MagicMock, patch

import hylianscan
from core.output import ANSI_ESCAPE_PATTERN
from core.tcp_live_display import TCPScanDisplay, render_sword_progress_bar
from modules.target import ResolvedAddress, TargetInfo
from modules.tcp_scanner import (
    PortScanResult,
    discover_open_port,
    probe_open_service,
    scan_tcp_ports,
)


class TCPScannerFlowTests(unittest.TestCase):
    """Validate scanner flow without real network connections."""

    def test_sword_progress_alignment_and_discovery_estimate(self) -> None:
        target = TargetInfo("localhost", "localhost", "127.0.0.1", False)
        with (
            patch("core.tcp_live_display.time.monotonic", side_effect=[100, 100, 113]),
            patch("core.tcp_live_display.supports_sword_symbols", return_value=True),
            patch("core.tcp_live_display.shutil.get_terminal_size", return_value=os.terminal_size((100, 24))),
            patch("core.tcp_live_display.write_dynamic_line") as render,
            patch("core.tcp_live_display.print_safe"),
        ):
            display = TCPScanDisplay(target, 10000)
            display.start_connect_scan()
            display.handle_progress(6200, 10000, 80)
        rendered = ANSI_ESCAPE_PATTERN.sub("", render.call_args.args[0])
        self.assertEqual(rendered,
            "TCP scan about : \u25c8\u256c[" + "\u2501" * 12 + "\u2500" * 8
            + "]\u25b7   62% \u00b7  6,200 / 10,000 ports \u00b7 ~8s left")

    def test_sword_progress_fits_narrow_terminals_and_ascii(self) -> None:
        target = TargetInfo("localhost", "localhost", "127.0.0.1", False)
        for columns in (17, 20, 21, 22, 30, 32, 33, 40, 80):
            for encoding in ("ascii", "cp1252", "utf-8"):
                with (
                    self.subTest(columns=columns, encoding=encoding),
                    io.TextIOWrapper(io.BytesIO(), encoding=encoding) as output,
                    patch("sys.stdout", output),
                    patch("core.tcp_live_display.shutil.get_terminal_size", return_value=os.terminal_size((columns, 24))),
                    patch("core.tcp_live_display.write_dynamic_line") as render,
                    patch("core.tcp_live_display.time.monotonic", side_effect=range(100, 110)),
                ):
                    display = TCPScanDisplay(target, 10000)
                    for completed, percentage in ((1, "  0%"), (11600, " 58%"), (19999, " 99%"), (20000, "100%")):
                        display.handle_progress(completed, 20000, 80)
                        rendered = ANSI_ESCAPE_PATTERN.sub("", render.call_args.args[0])
                        self.assertLess(len(rendered), columns)
                        self.assertNotIn("\n", rendered)
                        self.assertIn(percentage, rendered)
                        rendered.encode(encoding)
                    if encoding != "utf-8" and columns >= 33:
                        self.assertIn("o+[", rendered)
                        self.assertNotIn("\\u", rendered)
        with patch("core.tcp_live_display.supports_sword_symbols", return_value=False):
            for progress, expected in ((-1, "o+[----]>"), (0.5, "o+[##--]>"), (2, "o+[####]>")):
                self.assertEqual(ANSI_ESCAPE_PATTERN.sub("", render_sword_progress_bar(progress, 4)), expected)

    def test_sword_refresh_is_throttled_but_completion_and_findings_are_immediate(self) -> None:
        target = TargetInfo("localhost", "localhost", "127.0.0.1", False)
        with (
            patch("core.tcp_live_display.time.monotonic", side_effect=[100, 100, 100.01, 100.02, 100.11, 100.12]),
            patch("core.tcp_live_display.write_dynamic_line") as render,
            patch("core.tcp_live_display.clear_dynamic_line"),
            patch("core.tcp_live_display.print_safe") as print_line,
        ):
            display = TCPScanDisplay(target, 100)
            display.handle_progress(1, 100, 80)
            display.handle_progress(2, 100, 81)
            display.handle_open_port(PortScanResult(82, "HTTP", None, 0.01))
            print_line.assert_called_once()
            display.handle_progress(3, 100, 82)
            self.assertEqual(render.call_count, 1)
            display.handle_progress(99, 100, 83)
            self.assertEqual(render.call_count, 2)
            display.handle_progress(100, 100, 84)
            self.assertEqual(render.call_count, 3)
            self.assertIn("100%", render.call_args.args[0])

    def test_sword_line_clears_before_open_findings_and_service_probe(self) -> None:
        target = TargetInfo("localhost", "localhost", "127.0.0.1", False)
        output = io.StringIO()
        with patch("sys.stdout", output):
            display = TCPScanDisplay(target, 2)
            display.handle_progress(1, 2, 80)
            display.handle_open_port(PortScanResult(80, "HTTP", None, 0.01))
            display.handle_progress(2, 2, 81)
            display.start_service_probe(1)
            display.complete_service_probe(0.01)
            display.stop()
        rendered = output.getvalue()
        self.assertNotIn("\033[3A", rendered)
        self.assertNotIn("\033[J", rendered)
        self.assertEqual(rendered.count("\n"), 6)
        self.assertIn("[+] OPEN: 80/tcp", rendered)
        self.assertIn("Native Service Probing", rendered)
        self.assertNotIn("\033[3A", rendered.split("Service Probe completed", 1)[1])

    def test_scan_clears_sword_on_completion_failure_and_interruption(self) -> None:
        target = TargetInfo("localhost", "localhost", "127.0.0.1", False)
        for failure in (None, RuntimeError("failed"), KeyboardInterrupt()):
            with (
                self.subTest(failure=failure),
                patch("hylianscan.TCPScanDisplay") as display,
                patch("hylianscan.scan_tcp_ports", side_effect=failure, return_value="result"),
            ):
                if failure is None:
                    self.assertEqual(hylianscan.run_port_scan(target, [80], 1, 1), "result")
                else:
                    with self.assertRaises(type(failure)):
                        hylianscan.run_port_scan(target, [80], 1, 1)
                display.return_value.stop.assert_called_once_with()

    def test_live_progress_keeps_multi_address_counts_without_connection_label(self) -> None:
        target = TargetInfo(
            raw_input="example.com",
            target_host="example.com",
            resolved_ip="192.0.2.10",
            is_ip_address=False,
            address_family="dual-stack",
        )

        with patch("core.tcp_live_display.write_dynamic_line") as render:
            TCPScanDisplay(target, 1).handle_progress(1, 2, 80)

        rendered = render.call_args.args[0]
        self.assertIn("1 / 2", rendered)
        self.assertNotIn("connection attempts", rendered)
        self.assertNotIn("1 / 2 ports", rendered)

    def test_scan_tcp_ports_passes_max_rate_pacer_to_discovery_workers(self) -> None:
        fake_pacer = object()

        with (
            patch("modules.tcp_scanner.MaxRatePacer", return_value=fake_pacer) as pacer,
            patch("modules.tcp_scanner.discover_open_port", return_value=None) as discover,
        ):
            result = scan_tcp_ports(
                target_host="example.com",
                resolved_ip="127.0.0.1",
                ports=[80, 81],
                timeout=0.1,
                max_workers=1,
                max_rate=25.0,
            )

        pacer.assert_called_once_with(25.0)
        self.assertEqual(result.scanned_ports, 2)
        self.assertEqual(result.open_ports, ())
        self.assertTrue(discover.call_args_list)

        for call in discover.call_args_list:
            self.assertIs(call.args[4], fake_pacer)

    def test_scan_tcp_ports_passes_max_rate_pacer_to_service_probe_workers(self) -> None:
        fake_pacer = object()
        finding = PortScanResult(
            port=80,
            service="http",
            banner=None,
            response_time=0.01,
        )

        with (
            patch("modules.tcp_scanner.MaxRatePacer", return_value=fake_pacer),
            patch("modules.tcp_scanner.discover_open_port", return_value=finding),
            patch("modules.tcp_scanner.probe_open_service", return_value=finding) as probe,
        ):
            result = scan_tcp_ports(
                target_host="example.com",
                resolved_ip="127.0.0.1",
                ports=[80],
                timeout=0.1,
                max_workers=1,
                max_rate=10.0,
                http_probing=False,
            )

        self.assertEqual(len(result.open_ports), 1)
        self.assertIs(probe.call_args.args[4], fake_pacer)
        self.assertFalse(probe.call_args.args[7])

    def test_scan_tcp_ports_keeps_default_flow_without_max_rate(self) -> None:
        with (
            patch("modules.tcp_scanner.MaxRatePacer") as pacer,
            patch("modules.tcp_scanner.discover_open_port", return_value=None) as discover,
        ):
            result = scan_tcp_ports(
                target_host="example.com",
                resolved_ip="127.0.0.1",
                ports=[80],
                timeout=0.1,
                max_workers=1,
            )

        pacer.assert_not_called()
        self.assertEqual(result.scanned_ports, 1)
        self.assertEqual(result.open_ports, ())
        self.assertIsNone(discover.call_args.args[4])

    def test_scan_tcp_ports_skips_probe_callbacks_without_open_services(self) -> None:
        probe_start = MagicMock()
        probe_complete = MagicMock()

        with patch("modules.tcp_scanner.discover_open_port", return_value=None):
            scan_tcp_ports(
                target_host="example.com",
                resolved_ip="127.0.0.1",
                ports=[80],
                timeout=0.1,
                max_workers=1,
                service_probe_start_callback=probe_start,
                service_probe_complete_callback=probe_complete,
            )

        probe_start.assert_not_called()
        probe_complete.assert_not_called()

    def test_discover_open_port_uses_ipv6_socket_and_destination(self) -> None:
        fake_socket = MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        fake_socket.connect_ex.return_value = 0

        with patch("modules.tcp_scanner.socket.socket", return_value=fake_socket) as factory:
            finding = discover_open_port(
                "example.com",
                "2001:db8::10",
                443,
                timeout=0.1,
                address_family=socket.AF_INET6,
            )

        factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        fake_socket.connect_ex.assert_called_once_with(("2001:db8::10", 443, 0, 0))
        self.assertIsNotNone(finding)
        self.assertEqual(finding.address_family, "ipv6")

    def test_disabled_http_probing_keeps_discovery_without_opening_a_probe_socket(self) -> None:
        finding = PortScanResult(
            port=443,
            service="https",
            banner=None,
            response_time=0.01,
            web_url="https://example.com",
        )

        with patch("modules.tcp_scanner.socket.socket") as socket_factory:
            result = probe_open_service(
                "example.com",
                "127.0.0.1",
                finding,
                http_probing=False,
            )

        self.assertEqual(result.port, finding.port)
        self.assertEqual(result.probe["status"], "disabled")
        socket_factory.assert_not_called()

    def test_live_multiple_address_finding_identifies_its_address(self) -> None:
        target = TargetInfo(
            raw_input="example.com",
            target_host="example.com",
            resolved_ip="192.0.2.10",
            is_ip_address=False,
            address_family="dual-stack",
            addresses=(
                ResolvedAddress("192.0.2.10", socket.AF_INET),
                ResolvedAddress("192.0.2.11", socket.AF_INET),
            ),
        )
        finding = PortScanResult(
            80,
            "HTTP",
            None,
            0.01,
            address="192.0.2.11",
            address_family="ipv4",
        )

        with (
            patch("core.tcp_live_display.clear_dynamic_line"),
            patch("core.tcp_live_display.print_safe") as print_safe,
        ):
            TCPScanDisplay(target, 1).handle_open_port(finding)

        self.assertIn("80/tcp on 192.0.2.11 (IPv4)", print_safe.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
