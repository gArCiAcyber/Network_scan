"""Tests for passive discovery terminal output helpers."""

import io
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from core import passive_display
from core.passive_telemetry import PassiveActivityTelemetry
from modules.subdomain import ProviderRunResult


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
FORBIDDEN_CHARACTER_NAMES = ("Zelda", "Navi", "Impa", "Din", "Link", "Skull Kid")


class PassiveDiscoveryOutputTests(unittest.TestCase):
    """Validate passive discovery output remains provider-focused."""

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

        self.assertIn("SHEIKAH MAP", rendered)
        self.assertIn("Provider candidates: 8", rendered)
        self.assertIn("Unique names saved: 5", rendered)
        self.assertIn(
            "Output Path: output/example.com/20260628_120000/subdomains.txt",
            rendered,
        )
        self.assertNotIn(str(Path.cwd()), rendered)

    def test_provider_status_and_dns_validation_do_not_imply_live_services(self) -> None:
        providers = {"subfinder": ProviderRunResult(["www.example.com"], "completed", 0)}
        for quiet in (True, False):
            report = passive_display.build_passive_subdomain_summary(
                "example.com", 1, 1, Path("subdomains.txt"), quiet, providers)
            self.assertIn("names are passive candidates", report)
            self.assertRegex(report, r"subfinder\s+completed\s+1")
        providers["dnsx"] = ProviderRunResult(["www.example.com"], "completed", 0)
        report = passive_display.build_passive_subdomain_summary(
            "example.com", 1, 1, Path("subdomains.txt"), True, providers)
        self.assertIn("DNSx A/AAAA results; service reachability untested", report)
        providers["dnsx"] = ProviderRunResult([], "timed_out", reason="timeout")
        report = passive_display.build_passive_subdomain_summary(
            "example.com", 1, 0, Path("subdomains.txt"), True, providers)
        self.assertIn("DNS validation: incomplete", report)
        self.assertRegex(report, r"dnsx\s+timed_out\s+0")

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
