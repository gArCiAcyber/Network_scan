"""Tests for passive discovery terminal output helpers."""

import io
import os
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from core import passive_display
from core.passive_telemetry import PassiveActivityTelemetry
from core.terminal import DynamicBlockRenderer


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
FORBIDDEN_CHARACTER_NAMES = ("Zelda", "Navi", "Impa", "Din", "Link", "Skull Kid")


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

    def test_upstream_timeout_does_not_consume_process_timeout_event(self) -> None:
        telemetry = PassiveActivityTelemetry()
        raw = telemetry.map_provider_output("amass", "Amass stderr: upstream timeout; retrying")
        actual = telemetry.map_provider_output("amass", "Amass provider timed_out: Timed out after 180 seconds.")
        self.assertIn("diagnostic", raw)
        self.assertNotIn("preserving partial results", raw)
        self.assertIn("provider timed out", actual)
        spoof = telemetry.map_provider_output("amass", "Amass stderr: Amass provider completed: exit 0")
        self.assertIn("diagnostic", spoof)

    def test_progress_and_completion_are_visible(self) -> None:
        telemetry = PassiveActivityTelemetry()
        self.assertIn("15s / 180s; 42 candidates", telemetry.map_provider_output(
            "amass", "Amass progress: 15s / 180s; 42 candidates"))
        self.assertIn("exit 0", telemetry.map_provider_output(
            "amass", "Amass provider completed: exit 0; 42 candidates"))

    def test_show_passive_providers_marks_enabled_tools(self) -> None:
        output = io.StringIO()

        with redirect_stdout(output):
            passive_display.show_passive_providers(["subfinder", "amass"])

        rendered = ANSI_PATTERN.sub("", output.getvalue())

        self.assertIn("[*] Passive Discovery Providers:", rendered)
        self.assertIn("[+] Subfinder enabled", rendered)
        self.assertIn("[+] Amass enabled", rendered)

    def test_passive_telemetry_uses_provider_focused_messages(self) -> None:
        telemetry = PassiveActivityTelemetry()

        messages = [
            telemetry.map_lifecycle_event("provider started", "subfinder"),
            telemetry.map_provider_output("subfinder", "subfinder first result observed"),
            telemetry.map_lifecycle_event("provider timeout", "amass"),
            telemetry.map_merge_activity(),
        ]

        rendered = "\n".join(message for message in messages if message)

        self.assertIn("Running Subfinder passive enumeration", rendered)
        self.assertIn("Subfinder returned the first candidate", rendered)
        self.assertIn("Amass timed out; preserving partial results", rendered)
        self.assertIn("Normalizing provider results", rendered)

        for character_name in FORBIDDEN_CHARACTER_NAMES:
            self.assertNotIn(character_name, rendered)

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

    def test_passive_activity_line_uses_status_marker_for_duplicate_removal(self) -> None:
        rendered = ANSI_PATTERN.sub(
            "",
            passive_display.format_passive_activity_line(
                "[*] Removing duplicate subdomains..."
            ),
        )

        self.assertEqual(rendered, "[*] Removing duplicate subdomains...")


if __name__ == "__main__":
    unittest.main()
