"""Tests for target validation and resolution."""

import unittest
import socket
from unittest.mock import patch

from modules.target import (
    ADDRESS_FAMILY_IPV4,
    ADDRESS_FAMILY_IPV6,
    TargetResolutionError,
    resolve_target,
)


class TargetResolutionTests(unittest.TestCase):
    def test_resolve_target_separates_ipv4_and_ipv6_results(self) -> None:
        resolver_results = (
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::10", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0)),
        )

        with (
            patch("modules.target.socket.getaddrinfo", return_value=resolver_results),
            patch(
                "modules.target.socket.getnameinfo",
                side_effect=[("v4.example.test", 0), ("v6.example.test", 0)],
            ),
        ):
            target = resolve_target("example.test")

        self.assertEqual(target.resolved_ip, "192.0.2.10")
        self.assertEqual([address.address for address in target.ipv4_addresses], ["192.0.2.10"])
        self.assertEqual([address.address for address in target.ipv6_addresses], ["2001:db8::10"])
        self.assertEqual(target.reverse_dns["2001:db8::10"], "v6.example.test")

    def test_resolve_target_honors_explicit_ipv6_selection(self) -> None:
        resolver_results = (
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::10", 0, 0, 0)),
        )

        with (
            patch("modules.target.socket.getaddrinfo", return_value=resolver_results) as resolver,
            patch("modules.target.socket.getnameinfo", return_value=("v6.example.test", 0)),
        ):
            target = resolve_target("example.test", ADDRESS_FAMILY_IPV6)

        resolver.assert_called_once_with(
            "example.test",
            None,
            socket.AF_INET6,
            socket.SOCK_STREAM,
        )
        self.assertEqual(target.address_family, ADDRESS_FAMILY_IPV6)
        self.assertEqual(target.ipv4_addresses, ())
        self.assertEqual(target.ipv6_addresses[0].family, socket.AF_INET6)

    def test_ipv6_literal_is_supported(self) -> None:
        with patch(
            "modules.target.socket.getaddrinfo",
            return_value=((socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),),
        ), patch("modules.target.socket.getnameinfo", return_value=("localhost", 0)):
            target = resolve_target("::1", ADDRESS_FAMILY_IPV6)

        self.assertEqual(target.resolved_ip, "::1")
        self.assertTrue(target.is_ip_address)

    def test_explicit_ipv4_rejects_an_ipv6_literal(self) -> None:
        with self.assertRaises(TargetResolutionError):
            resolve_target("::1", ADDRESS_FAMILY_IPV4)


if __name__ == "__main__":
    unittest.main()
