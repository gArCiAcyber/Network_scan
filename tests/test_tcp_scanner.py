"""Tests for TCP scanner orchestration helpers."""

import socket
import unittest
from unittest.mock import MagicMock, patch

from core.tcp_live_display import TCPScanDisplay
from modules.target import ResolvedAddress, TargetInfo
from modules.tcp_scanner import (
    PortScanResult,
    discover_open_port,
    probe_open_service,
    scan_tcp_ports,
)


class TCPScannerFlowTests(unittest.TestCase):
    """Validate scanner flow without real network connections."""

    def test_live_progress_labels_address_port_work_as_connection_attempts(self) -> None:
        target = TargetInfo(
            raw_input="example.com",
            target_host="example.com",
            resolved_ip="192.0.2.10",
            is_ip_address=False,
            address_family="dual-stack",
        )

        with patch("core.tcp_live_display.write_dynamic_line") as write_line:
            TCPScanDisplay(target, 1).handle_progress(1, 2, 80)

        rendered = write_line.call_args.args[0]
        self.assertIn("1/2 connection attempts", rendered)
        self.assertNotIn("1/2 ports", rendered)

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

        self.assertIs(result, finding)
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
