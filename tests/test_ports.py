"""Tests for TCP port metadata helpers."""

import unittest

from modules.ports import (
    COMMON_PORTS,
    TOP_400_TCP_PORTS,
    build_web_url,
    get_service_name,
    normalize_ports,
)


class PortHelperTests(unittest.TestCase):
    """Validate pure TCP port helper behavior."""

    def test_normalize_ports_deduplicates_and_sorts(self) -> None:
        self.assertEqual(normalize_ports([443, 80, 443, "22"]), (22, 80, 443))

    def test_normalize_ports_uses_default_common_ports(self) -> None:
        self.assertEqual(normalize_ports(), tuple(sorted(COMMON_PORTS)))

    def test_get_service_name_returns_known_and_unknown_services(self) -> None:
        self.assertEqual(get_service_name(80), "HTTP")
        self.assertEqual(get_service_name(443), "HTTPS")
        self.assertEqual(get_service_name(110), "POP3")
        self.assertEqual(get_service_name(143), "IMAP")
        self.assertEqual(get_service_name(65001), "Unknown")

    def test_build_web_url_omits_default_web_ports(self) -> None:
        self.assertEqual(build_web_url("192.0.2.10", 80), "http://192.0.2.10")
        self.assertEqual(build_web_url("192.0.2.10", 443), "https://192.0.2.10")

    def test_build_web_url_includes_alternate_web_ports(self) -> None:
        self.assertEqual(build_web_url("192.0.2.10", 8080), "http://192.0.2.10:8080")
        self.assertEqual(build_web_url("192.0.2.10", 8443), "https://192.0.2.10:8443")
        self.assertEqual(build_web_url("192.0.2.10", 2053), "https://192.0.2.10:2053")

    def test_build_web_url_brackets_ipv6_literals(self) -> None:
        self.assertEqual(build_web_url("2001:db8::10", 80), "http://[2001:db8::10]")
        self.assertEqual(
            build_web_url("2001:db8::10", 8443),
            "https://[2001:db8::10]:8443",
        )

    def test_build_web_url_returns_none_for_non_web_ports(self) -> None:
        self.assertIsNone(build_web_url("192.0.2.10", 22))

    def test_top_400_ports_are_unique_and_rank_common_services_first(self) -> None:
        self.assertEqual(len(TOP_400_TCP_PORTS), 400)
        self.assertEqual(len(set(TOP_400_TCP_PORTS)), 400)
        self.assertEqual(TOP_400_TCP_PORTS[:5], [80, 23, 443, 21, 22])

    def test_probe_ports_share_service_and_web_metadata(self) -> None:
        expected_services = {
            465: "SMTPS",
            587: "SMTP",
            990: "FTPS",
            2121: "FTP",
            8008: "HTTP",
            8888: "HTTP",
        }
        for port, service in expected_services.items():
            with self.subTest(port=port):
                self.assertEqual(get_service_name(port), service)

        self.assertEqual(build_web_url("192.0.2.10", 8008), "http://192.0.2.10:8008")
        self.assertEqual(build_web_url("192.0.2.10", 8888), "http://192.0.2.10:8888")


if __name__ == "__main__":
    unittest.main()
