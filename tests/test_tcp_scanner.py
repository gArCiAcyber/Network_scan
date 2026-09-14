"""Tests for TCP scanner orchestration helpers."""

import socket
import unittest
from unittest.mock import MagicMock, patch

from modules.tcp_scanner import PortScanResult, discover_open_port, scan_tcp_ports


class TCPScannerFlowTests(unittest.TestCase):
    """Validate scanner flow without real network connections."""

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
            )

        self.assertEqual(len(result.open_ports), 1)
        self.assertIs(probe.call_args.args[4], fake_pacer)

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


if __name__ == "__main__":
    unittest.main()
