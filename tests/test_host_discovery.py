"""Tests for optional ICMP and TCP host discovery."""

import errno
import socket
import unittest
from unittest.mock import MagicMock, patch

from hylianscan import run_host_discovery
from modules.host_discovery import HostDiscoveryResult, discover_host
from modules.target import ResolvedAddress, TargetInfo


class HostDiscoveryTests(unittest.TestCase):
    def test_orchestration_keeps_discovery_evidence_for_filtered_addresses(self) -> None:
        addresses = (
            ResolvedAddress("192.0.2.10", socket.AF_INET),
            ResolvedAddress("2001:db8::10", socket.AF_INET6),
        )
        target = TargetInfo(
            raw_input="example.com",
            target_host="example.com",
            resolved_ip=addresses[0].address,
            is_ip_address=False,
            addresses=addresses,
            address_family="dual-stack",
        )
        discovery_results = (
            HostDiscoveryResult(addresses[0], "tcp", True, 0.01),
            HostDiscoveryResult(addresses[1], "tcp", False, 1.0, "timed out"),
        )

        with patch("hylianscan.discover_hosts", return_value=discovery_results):
            scan_target, evidence = run_host_discovery(target, "tcp", 1.0)

        self.assertEqual(scan_target.address_records, (addresses[0],))
        self.assertEqual(evidence, discovery_results)

    def test_tcp_discovery_uses_ipv6_socket_and_sockaddr(self) -> None:
        address = ResolvedAddress("2001:db8::10", socket.AF_INET6)
        fake_socket = MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        fake_socket.connect_ex.return_value = errno.ECONNREFUSED

        with patch("modules.host_discovery.socket.socket", return_value=fake_socket) as factory:
            result = discover_host(address, "tcp", tcp_ports=(443,))

        factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        fake_socket.connect_ex.assert_called_once_with(("2001:db8::10", 443, 0, 0))
        self.assertTrue(result.is_up)

    def test_icmp_discovery_uses_shell_free_ping(self) -> None:
        address = ResolvedAddress("192.0.2.10", socket.AF_INET)
        completed = MagicMock(returncode=0)

        with patch("modules.host_discovery.subprocess.run", return_value=completed) as runner:
            result = discover_host(address, "icmp")

        self.assertTrue(result.is_up)
        self.assertEqual(runner.call_args.kwargs["shell"], False)
        self.assertEqual(runner.call_args.args[0][-1], "192.0.2.10")


if __name__ == "__main__":
    unittest.main()
