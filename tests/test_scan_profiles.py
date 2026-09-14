"""Tests for complete scan profile defaults and overrides."""

import argparse
import unittest
from unittest.mock import patch

from core.cli import (
    get_scan_profile,
    parse_arguments,
    parse_ports_list,
    resolve_host_discovery,
    resolve_http_probing,
    resolve_max_rate,
    resolve_scan_stance,
    validate_mode,
)
from core.info_commands import format_scan_profiles_listing
from modules.port_profiles import resolve_port_profile
from modules.scan_profiles import resolve_scan_profile


def build_args(**overrides: object) -> argparse.Namespace:
    """Build the TCP options used by profile resolution."""
    values = {
        "scan_profile": None,
        "port_profile": None,
        "ports": None,
        "top_ports": None,
        "stance": None,
        "threads": None,
        "timeout": None,
        "max_rate": None,
        "host_discovery": None,
        "http_probing": None,
        "subfinder": False,
        "amass": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class ScanProfileTests(unittest.TestCase):
    """Validate bundled profile behavior."""

    def test_profiles_apply_complete_defaults(self) -> None:
        expected = {
            "quick": (50, 0.75, None, False),
            "web": (50, 1.0, None, True),
            "cautious": (10, 2.0, 10.0, True),
        }

        for name, settings in expected.items():
            with self.subTest(profile=name):
                args = build_args(scan_profile=name)
                profile = get_scan_profile(args)
                stance = resolve_scan_stance(args)

                self.assertIsNotNone(profile)
                self.assertEqual(
                    parse_ports_list(args),
                    list(resolve_port_profile(profile.port_profile).ports),
                )
                self.assertEqual(
                    (
                        stance.workers,
                        stance.timeout,
                        resolve_max_rate(args),
                        resolve_http_probing(args),
                    ),
                    settings,
                )
                self.assertIsNone(resolve_host_discovery(args))

    def test_explicit_flags_override_profile_defaults(self) -> None:
        args = build_args(
            scan_profile="cautious",
            ports="443",
            threads=25,
            timeout=3.0,
            max_rate=2.0,
            host_discovery="tcp",
            http_probing=False,
        )
        stance = resolve_scan_stance(args)

        self.assertEqual(parse_ports_list(args), [443])
        self.assertEqual((stance.workers, stance.timeout), (25, 3.0))
        self.assertEqual(resolve_max_rate(args), 2.0)
        self.assertEqual(resolve_host_discovery(args), "tcp")
        self.assertFalse(resolve_http_probing(args))

    def test_profile_names_are_case_insensitive_and_invalid_names_fail(self) -> None:
        self.assertEqual(resolve_scan_profile(" WEB ").name, "web")

        with self.assertRaisesRegex(ValueError, "Invalid --profile value"):
            resolve_scan_profile("unknown")

    def test_cli_and_listing_expose_complete_profiles(self) -> None:
        with patch("sys.argv", ["hylianscan", "example.com", "--profile", "web"]):
            args = parse_arguments()

        listing = format_scan_profiles_listing()
        self.assertEqual(args.scan_profile, "web")
        self.assertIn("quick", listing)
        self.assertIn("web", listing)
        self.assertIn("cautious", listing)
        self.assertIn("HTTP Probing", listing)

    def test_http_status_filter_requires_profile_http_probing(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTP probing is enabled"):
            validate_mode(build_args(scan_profile="quick", match_code="200"))

        validate_mode(
            build_args(
                scan_profile="quick",
                match_code="200",
                http_probing=True,
            )
        )


if __name__ == "__main__":
    unittest.main()
