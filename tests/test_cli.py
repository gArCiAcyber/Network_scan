"""Tests for pure CLI argument helper logic."""

import argparse
import io
import unittest
from unittest.mock import patch

from core.cli import (
    get_passive_providers,
    is_quiet_mode,
    parse_arguments,
    parse_custom_ports,
    parse_ports_list,
    resolve_port_profile_label,
    resolve_scan_scope_label,
    validate_max_rate,
    validate_mode,
    validate_port,
    validate_threads,
    validate_timeout,
)
from modules.port_profiles import resolve_port_profile
from modules.ports import TOP_400_TCP_PORTS


def build_args(
    ports: str | None = None,
    top_ports: int | None = None,
    port_profile: str | None = None,
    subfinder: bool = False,
    amass: bool = False,
    quiet: bool = False,
    max_rate: float | None = None,
) -> argparse.Namespace:
    """Build a minimal argparse namespace for CLI helper tests."""
    return argparse.Namespace(
        ports=ports,
        top_ports=top_ports,
        port_profile=port_profile,
        subfinder=subfinder,
        amass=amass,
        quiet=quiet,
        max_rate=max_rate,
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

    def test_parse_ports_list_handles_port_profile_name(self) -> None:
        expected_ports = list(resolve_port_profile("web").ports)

        self.assertEqual(parse_ports_list(build_args(port_profile="web")), expected_ports)

    def test_parse_ports_list_handles_port_profile_alias(self) -> None:
        expected_ports = list(resolve_port_profile("sheikah").ports)

        self.assertEqual(
            parse_ports_list(build_args(port_profile="sheikah")),
            expected_ports,
        )

    def test_parse_ports_list_rejects_unknown_port_profile(self) -> None:
        with self.assertRaisesRegex(ValueError, "Invalid --port-profile value"):
            parse_ports_list(build_args(port_profile="unknown-profile"))

    def test_parse_ports_list_rejects_ports_and_port_profile_together(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports_list(build_args(ports="80", port_profile="web"))

    def test_parse_ports_list_rejects_top_ports_and_port_profile_together(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports_list(build_args(top_ports=10, port_profile="web"))

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

    def test_validate_max_rate_accepts_none_and_positive_values(self) -> None:
        self.assertIsNone(validate_max_rate(None))
        self.assertEqual(validate_max_rate(100.0), 100.0)

    def test_validate_max_rate_rejects_zero_and_negative_values(self) -> None:
        for max_rate in (0.0, -0.1, -10.0):
            with self.subTest(max_rate=max_rate):
                with self.assertRaises(ValueError):
                    validate_max_rate(max_rate)

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
        self.assertEqual(
            resolve_scan_scope_label(build_args(port_profile="sheikah")),
            "Port Profile: web / sheikah",
        )

    def test_resolve_port_profile_label_returns_profile_and_alias(self) -> None:
        self.assertIsNone(resolve_port_profile_label(build_args()))
        self.assertEqual(
            resolve_port_profile_label(build_args(port_profile="castle")),
            "admin / castle",
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
            build_args(port_profile="quick", subfinder=True),
        )

        for args in invalid_args:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    validate_mode(args)

    def test_parse_arguments_accepts_quiet_flag(self) -> None:
        with patch("sys.argv", ["hylianscan", "example.com", "--quiet"]):
            args = parse_arguments()

        self.assertEqual(args.target, "example.com")
        self.assertTrue(args.quiet)

    def test_version_output_does_not_require_target(self) -> None:
        output = io.StringIO()

        with (
            patch("sys.argv", ["hylianscan", "--version"]),
            patch("sys.stdout", output),
            self.assertRaises(SystemExit) as exit_context,
        ):
            parse_arguments()

        self.assertEqual(exit_context.exception.code, 0)
        self.assertEqual(output.getvalue(), "hylianscan 1.0.0-dev\n")

    def test_help_output_remains_available_without_target(self) -> None:
        output = io.StringIO()

        with (
            patch("sys.argv", ["hylianscan", "--help"]),
            patch("sys.stdout", output),
            self.assertRaises(SystemExit) as exit_context,
        ):
            parse_arguments()

        self.assertEqual(exit_context.exception.code, 0)
        self.assertIn("usage: hylianscan", output.getvalue())
        self.assertIn("--version", output.getvalue())

    def test_parse_arguments_accepts_port_profile_name(self) -> None:
        with patch("sys.argv", ["hylianscan", "example.com", "--port-profile", "web"]):
            args = parse_arguments()

        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.port_profile, "web")

    def test_parse_arguments_accepts_port_profile_alias(self) -> None:
        with patch(
            "sys.argv",
            ["hylianscan", "example.com", "--port-profile", "sheikah"],
        ):
            args = parse_arguments()

        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.port_profile, "sheikah")

    def test_parse_arguments_accepts_passive_provider_path_flags(self) -> None:
        with patch(
            "sys.argv",
            [
                "hylianscan",
                "example.com",
                "-s",
                "-a",
                "--subfinder-path",
                "/opt/tools/subfinder",
                "--amass-path",
                "/opt/tools/amass",
            ],
        ):
            args = parse_arguments()

        self.assertEqual(args.target, "example.com")
        self.assertTrue(args.subfinder)
        self.assertTrue(args.amass)
        self.assertEqual(args.subfinder_path, "/opt/tools/subfinder")
        self.assertEqual(args.amass_path, "/opt/tools/amass")

    def test_parse_arguments_accepts_max_rate_flag(self) -> None:
        with patch("sys.argv", ["hylianscan", "example.com", "--max-rate", "100"]):
            args = parse_arguments()

        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.max_rate, 100.0)

    def test_parse_arguments_rejects_non_numeric_max_rate(self) -> None:
        with (
            patch("sys.argv", ["hylianscan", "example.com", "--max-rate", "fast"]),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            with self.assertRaises(SystemExit):
                parse_arguments()

    def test_is_quiet_mode_normalizes_missing_and_present_values(self) -> None:
        self.assertFalse(is_quiet_mode(argparse.Namespace()))
        self.assertFalse(is_quiet_mode(build_args(quiet=False)))
        self.assertTrue(is_quiet_mode(build_args(quiet=True)))


if __name__ == "__main__":
    unittest.main()
