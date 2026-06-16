"""Tests for TCP scan orientation display helpers."""

import argparse
import io
import re
import unittest
from contextlib import redirect_stdout

import hylianscan
from modules.scan_stance import ScanStance
from modules.target import TargetInfo


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(value: str) -> str:
    """Remove ANSI escape codes from captured terminal output."""
    return ANSI_PATTERN.sub("", value)


class ScanOrientationTests(unittest.TestCase):
    """Validate effective TCP scan configuration display behavior."""

    def test_default_stance_values_are_reported_without_overrides(self) -> None:
        args = argparse.Namespace(threads=None, timeout=None, max_rate=None)

        self.assertFalse(hylianscan.has_scan_config_overrides(args))
        self.assertEqual(
            hylianscan.format_scan_config_source(False),
            "Default Stance Values",
        )

    def test_manual_threads_timeout_or_max_rate_are_custom_overrides(self) -> None:
        override_args = (
            argparse.Namespace(threads=200, timeout=None, max_rate=None),
            argparse.Namespace(threads=None, timeout=0.75, max_rate=None),
            argparse.Namespace(threads=None, timeout=None, max_rate=100.0),
        )

        for args in override_args:
            with self.subTest(args=args):
                self.assertTrue(hylianscan.has_scan_config_overrides(args))

        self.assertEqual(
            hylianscan.format_scan_config_source(True),
            "User Overrides",
        )

    def test_max_rate_label_distinguishes_unlimited_and_configured_values(self) -> None:
        self.assertEqual(hylianscan.format_max_rate_label(None), "Unlimited")
        self.assertEqual(hylianscan.format_max_rate_label(100.0), "100/s")
        self.assertEqual(hylianscan.format_max_rate_label(12.5), "12.5/s")

    def test_target_orientation_shows_effective_scan_configuration(self) -> None:
        target = TargetInfo(
            raw_input="example.com",
            target_host="example.com",
            resolved_ip="93.184.216.34",
            is_ip_address=False,
        )
        stance = ScanStance(
            name="fast",
            lore_alias="Din",
            workers=300,
            timeout=0.75,
        )

        output = io.StringIO()
        with redirect_stdout(output):
            hylianscan.show_target_orientation(
                target=target,
                stance=stance,
                port_count=1000,
                max_rate=100.0,
                has_overrides=True,
            )

        rendered = strip_ansi(output.getvalue())

        self.assertIn("Stance        : fast (Din)", rendered)
        self.assertIn("Workers       : 300", rendered)
        self.assertIn("Timeout       : 0.75s", rendered)
        self.assertIn("Max Rate      : 100/s", rendered)
        self.assertIn("Config Source : User Overrides", rendered)
        self.assertIn("Scan Phase    : Hylian TCP Connect Scan", rendered)
        self.assertIn("Port Scope    : 1000 ports", rendered)


if __name__ == "__main__":
    unittest.main()
