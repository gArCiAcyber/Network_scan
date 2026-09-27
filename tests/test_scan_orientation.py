"""Tests for the concise TCP scan header."""

import io
import re
import socket
import unittest
from contextlib import redirect_stdout

import hylianscan
from modules.scan_stance import ScanStance
from modules.target import ResolvedAddress, TargetInfo


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def render_orientation(target: TargetInfo, port_count: int = 3, **options: object) -> str:
    output = io.StringIO()
    stance = ScanStance("balanced", "Nayru", 50, 1.0)
    with redirect_stdout(output):
        hylianscan.show_target_orientation(target, stance, port_count, **options)
    return ANSI_PATTERN.sub("", output.getvalue())


class ScanOrientationTests(unittest.TestCase):
    def test_header_shows_actual_addresses_and_port_scope_once(self) -> None:
        target = TargetInfo(
            raw_input="example.com",
            target_host="example.com",
            resolved_ip="192.0.2.10",
            is_ip_address=False,
            addresses=(
                ResolvedAddress("192.0.2.10", socket.AF_INET, "ptr.example.com"),
                ResolvedAddress("192.0.2.11", socket.AF_INET, "ptr.example.com"),
            ),
            address_family="dual-stack",
        )

        rendered = render_orientation(target)

        self.assertIn("[*] TCP Connect Scan:", rendered)
        self.assertIn("Target        : example.com", rendered)
        self.assertIn("Resolved IPs  : 192.0.2.10, 192.0.2.11", rendered)
        self.assertIn("Port Scope    : 3 ports per address", rendered)
        self.assertIn("Workers       : 50", rendered)
        self.assertIn("Timeout       : 1.00s", rendered)
        self.assertNotIn("Address Mode", rendered)
        self.assertNotIn("Reverse DNS", rendered)
        self.assertNotIn("ptr.example.com", rendered)
        self.assertNotIn("Max Rate", rendered)
        self.assertNotIn("Config Source", rendered)
        self.assertNotIn("HTTP Probing", rendered)

    def test_header_shows_selected_optional_controls(self) -> None:
        target = TargetInfo(
            raw_input="fe80::1",
            target_host="fe80::1",
            resolved_ip="fe80::1",
            is_ip_address=True,
            addresses=(ResolvedAddress("fe80::1", socket.AF_INET6, scope_id=4),),
            address_family="ipv6",
        )

        rendered = render_orientation(
            target,
            max_rate=12.5,
            host_discovery="tcp",
            http_probing=False,
            nmap_enabled=True,
            match_codes=[200, 301],
        )

        self.assertIn("Resolved IP   : fe80::1%4", rendered)
        self.assertIn("Max Rate      : 12.5 connection starts/s", rendered)
        self.assertIn("Host Discovery: tcp", rendered)
        self.assertIn("HTTP Probing  : Disabled", rendered)
        self.assertIn("Nmap Enrichment: Enabled (post-scan)", rendered)
        self.assertIn("HTTP Filter   : Status codes 200, 301", rendered)

    def test_header_supports_legacy_single_address_target(self) -> None:
        target = TargetInfo("192.0.2.10", "192.0.2.10", "192.0.2.10", True)
        rendered = render_orientation(target, port_count=1)
        self.assertIn("Resolved IP   : 192.0.2.10", rendered)
        self.assertIn("Port Scope    : 1 port per address", rendered)


if __name__ == "__main__":
    unittest.main()
