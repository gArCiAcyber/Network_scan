"""Tests for pure CLI argument helper logic."""

import argparse
import unittest

from core.cli import (
    get_passive_providers,
    parse_custom_ports,
    parse_ports_list,
    resolve_scan_scope_label,
    validate_mode,
    validate_port,
    validate_threads,
    validate_timeout,
)
from modules.ports import TOP_400_TCP_PORTS


def build_args(
    ports: str | None = None,
    top_ports: int | None = None,
    subfinder: bool = False,
    amass: bool = False,
) -> argparse.Namespace:
    """Build a minimal argparse namespace for CLI helper tests."""
    return argparse.Namespace(
        ports=ports,
        top_ports=top_ports,
        subfinder=subfinder,
        amass=amass,
    )


class CLIHelperTests(unittest.TestCase):
    """Validate pure command-line helper behavior."""

    def test_validate_port_accepts_valid_ports(self) -> None:
        self.assertEqual(validate_port(1), 1)
        self.assertEqual(validate_port(80), 80)
        self.assertEqual(validate_port(65535), 65535)

    def test_validate_port_rejects_invalid_ports(self) -> None:
        for port in (0, -1, 65536):
            with self.subTest(port=port):
                with self.assertRaises(ValueError):
                    validate_port(port)

    def test_parse_custom_ports_parses_comma_separated_ports(self) -> None:
        self.assertEqual(parse_custom_ports("80,443,8080"), [80, 443, 8080])

    def test_parse_custom_ports_parses_ranges(self) -> None:
        self.assertEqual(parse_custom_ports("20-22"), [20, 21, 22])

    def test_parse_custom_ports_deduplicates_and_sorts_ports(self) -> None:
        self.assertEqual(parse_custom_ports("443,80,443,22-23,22"), [22, 23, 80, 443])

    def test_parse_custom_ports_dash_returns_full_tcp_range(self) -> None:
        ports = parse_custom_ports("-")

        self.assertEqual(ports[0], 1)
        self.assertEqual(ports[-1], 65535)
        self.assertEqual(len(ports), 65535)

    def test_parse_ports_list_rejects_ports_and_top_ports_together(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports_list(build_args(ports="80", top_ports=10))

    def test_parse_ports_list_handles_top_ports(self) -> None:
        self.assertEqual(parse_ports_list(build_args(top_ports=5)), TOP_400_TCP_PORTS[:5])

    def test_parse_ports_list_rejects_invalid_top_ports_values(self) -> None:
        invalid_values = (0, -1, len(TOP_400_TCP_PORTS) + 1)

        for top_ports in invalid_values:
            with self.subTest(top_ports=top_ports):
                with self.assertRaises(ValueError):
                    parse_ports_list(build_args(top_ports=top_ports))

    def test_validate_timeout_rejects_zero_and_negative_values(self) -> None:
        for timeout in (0.0, -0.1, -5.0):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    validate_timeout(timeout)

    def test_validate_threads_rejects_zero_and_negative_values(self) -> None:
        for threads in (0, -1, -10):
            with self.subTest(threads=threads):
                with self.assertRaises(ValueError):
                    validate_threads(threads)

    def test_resolve_scan_scope_label_returns_expected_labels(self) -> None:
        self.assertEqual(resolve_scan_scope_label(build_args()), "Default Target List")
        self.assertEqual(
            resolve_scan_scope_label(build_args(ports="80")),
            "Custom Port List",
        )
        self.assertEqual(
            resolve_scan_scope_label(build_args(top_ports=10)),
            "Selected Port List",
        )

    def test_get_passive_providers_returns_selected_providers(self) -> None:
        self.assertEqual(get_passive_providers(build_args()), [])
        self.assertEqual(get_passive_providers(build_args(subfinder=True)), ["subfinder"])
        self.assertEqual(get_passive_providers(build_args(amass=True)), ["amass"])
        self.assertEqual(
            get_passive_providers(build_args(subfinder=True, amass=True)),
            ["subfinder", "amass"],
        )

    def test_validate_mode_rejects_passive_discovery_mixed_with_port_flags(self) -> None:
        invalid_args = (
            build_args(ports="80", subfinder=True),
            build_args(top_ports=10, amass=True),
        )

        for args in invalid_args:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    validate_mode(args)


if __name__ == "__main__":
    unittest.main()
