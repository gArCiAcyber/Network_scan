"""Tests for passive discovery terminal output helpers."""

import io
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import hylianscan
from core.passive_telemetry import PassiveActivityTelemetry


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
FORBIDDEN_CHARACTER_NAMES = ("Zelda", "Navi", "Impa", "Din", "Link", "Skull Kid")


class PassiveDiscoveryOutputTests(unittest.TestCase):
    """Validate passive discovery output remains provider-focused."""

    def test_show_passive_providers_marks_enabled_tools(self) -> None:
        output = io.StringIO()

        with redirect_stdout(output):
            hylianscan.show_passive_providers(["subfinder", "amass"])

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

        summary = hylianscan.build_passive_subdomain_summary(
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
            hylianscan.format_passive_activity_line("[*] Removing duplicate subdomains..."),
        )

        self.assertEqual(rendered, "[*] Removing duplicate subdomains...")


if __name__ == "__main__":
    unittest.main()
