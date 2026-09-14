"""Tests for optional ICMP and TCP host discovery."""

import errno
import socket
import unittest
from unittest.mock import MagicMock, patch

from modules.host_discovery import discover_host
from modules.target import ResolvedAddress


class HostDiscoveryTests(unittest.TestCase):
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
