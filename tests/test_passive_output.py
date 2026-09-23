"""Tests for passive discovery terminal output helpers."""

import io
import os
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from core import passive_display
from core.terminal import DynamicBlockRenderer


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


class PassiveDiscoveryOutputTests(unittest.TestCase):
    """Validate passive discovery output remains provider-focused."""

    def test_live_block_clips_wrapping_rows_and_limits_height(self) -> None:
        output = io.StringIO()
        renderer = DynamicBlockRenderer()
        with (redirect_stdout(output), patch("core.terminal.shutil.get_terminal_size",
                                             return_value=os.terminal_size((20, 3)))):
            lines = ["older activity", "\033[92m" + "x" * 2000 + "\033[0m",
                     "\033[31m" + "界e\u0301" * 20 + "\033[0m"]
            renderer.render(lines)
            renderer.render(lines)
            renderer.clear()
        raw = output.getvalue()
        rendered = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw).replace("\r", "")
        self.assertEqual(rendered.splitlines(), ["x" * 19, "界e\u0301" * 6] * 2)
        self.assertEqual(raw.count("\033[2A"), 2)
        self.assertIn("\033[92m", raw)
        self.assertNotIn("older activity", raw)

    def test_provider_status_stops_spinner_and_reports_final_count(self) -> None:
        output = io.StringIO()
        display = passive_display.PassiveDiscoveryDisplay()
        with redirect_stdout(output):
            display.start_provider("amass")
            display.update_count(42)
            display.finish_provider("completed", 57)
            self.assertIsNone(display._thread)
        rendered = ANSI_PATTERN.sub("", output.getvalue())
        self.assertIn("[>] Amass", rendered)
        self.assertIn("42 so far", rendered)
        self.assertIn("[+] Amass completed · 57 found", rendered)

    def test_timeout_reports_partial_count_and_stops_spinner(self) -> None:
        output = io.StringIO()
        display = passive_display.PassiveDiscoveryDisplay()
        with redirect_stdout(output):
            display.start_provider("dnsx")
            display.finish_provider("timed_out", 42)
        self.assertIn("[!] DNSx timeout · 42 found", ANSI_PATTERN.sub("", output.getvalue()))
        self.assertIsNone(display._thread)

    def test_enabled_providers_keep_their_colors(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            passive_display.show_passive_providers(["subfinder", "amass", "dnsx"])

        raw = output.getvalue()
        rendered = ANSI_PATTERN.sub("", raw)
        for label in ("Subfinder enabled", "Amass enabled", "DNSx enabled"):
            self.assertIn(label, rendered)
        self.assertIn(passive_display.PASSIVE_PROVIDER_LABELS["subfinder"][1], raw)
        self.assertIn(passive_display.PASSIVE_PROVIDER_LABELS["amass"][1], raw)
        self.assertIn(passive_display.PASSIVE_PROVIDER_LABELS["dnsx"][1], raw)

    def test_passive_summary_uses_raw_unique_counts_and_relative_path(self) -> None:
        output_path = Path("output") / "example.com" / "20260628_120000" / "subdomains.txt"

        summary = passive_display.build_passive_subdomain_summary(
            domain="example.com",
            raw_discovery_count=8,
            unique_subdomain_count=5,
            output_path=output_path,
        )
        rendered = ANSI_PATTERN.sub("", summary)

        self.assertIn("[+] SHEIKAH MAP UPDATED", rendered)
        self.assertIn("[+] Raw Discoveries    : 8", rendered)
        self.assertIn("[+] Unique Subdomains  : 5", rendered)
        self.assertIn(
            "Slate Database     : output/example.com/20260628_120000/subdomains.txt",
            rendered,
        )
        self.assertNotIn(str(Path.cwd()), rendered)

if __name__ == "__main__":
    unittest.main()
