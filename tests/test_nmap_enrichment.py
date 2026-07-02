"""Tests for optional live Nmap enrichment orchestration."""

import io
import unittest
from unittest.mock import patch

import hylianscan
from modules.nmap_enrichment import (
    format_nmap_enrichment_skipped,
    format_nmap_enrichment_summary,
)
from modules.nmap_xml import parse_nmap_xml_text
from modules.target import TargetInfo
from modules.tcp_scanner import PortScanResult, ScanResult


NMAP_ENRICHMENT_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -Pn -n -p 80 -oX - 127.0.0.1"
         start="1710000000" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def make_target() -> TargetInfo:
    """Build a stable resolved target fixture."""
    return TargetInfo(
        raw_input="example.com",
        target_host="example.com",
        resolved_ip="127.0.0.1",
        is_ip_address=False,
    )


def make_scan_result(open_ports: tuple[PortScanResult, ...]) -> ScanResult:
    """Build a stable scan result fixture."""
    return ScanResult(
        target_host="example.com",
        resolved_ip="127.0.0.1",
        scanned_ports=1,
        open_ports=open_ports,
        duration=0.01,
    )


def make_open_port(port: int = 80) -> PortScanResult:
    """Build a stable open-port fixture."""
    return PortScanResult(
        port=port,
        service="http",
        banner=None,
        response_time=0.01,
    )


class NmapEnrichmentFormattingTests(unittest.TestCase):
    """Validate terminal formatting for live Nmap enrichment."""

    def test_summary_includes_status_target_ports_and_service_details(self) -> None:
        import_result = parse_nmap_xml_text(NMAP_ENRICHMENT_XML)
        summary = format_nmap_enrichment_summary(import_result, "127.0.0.1", [80])

        self.assertIn("Nmap Enrichment", summary)
        self.assertIn("Status: completed", summary)
        self.assertIn("Target: 127.0.0.1", summary)
        self.assertIn("Ports enriched: 80", summary)
        self.assertIn("80/tcp", summary)
        self.assertIn("http", summary)
        self.assertIn("nginx 1.24", summary)
        self.assertIn("method=probed", summary)
        self.assertIn("confidence=high", summary)

    def test_skipped_message_uses_standard_prefix(self) -> None:
        self.assertEqual(
            format_nmap_enrichment_skipped("no open TCP ports found."),
            "Nmap enrichment skipped: no open TCP ports found.",
        )


class NmapEnrichmentMainTests(unittest.TestCase):
    """Validate main orchestration for optional live Nmap enrichment."""

    def test_main_does_not_call_nmap_runner_without_nmap_flag(self) -> None:
        scan_result = make_scan_result((make_open_port(),))

        with (
            patch("sys.argv", ["hylianscan", "example.com", "-p", "80", "--quiet"]),
            patch("sys.stdout", io.StringIO()),
            patch("hylianscan.resolve_target", return_value=make_target()),
            patch("hylianscan.run_port_scan", return_value=scan_result),
            patch("hylianscan.run_nmap_service_version_scan") as nmap_runner,
        ):
            hylianscan.main()

        nmap_runner.assert_not_called()

    def test_main_calls_nmap_runner_for_native_open_ports(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = parse_nmap_xml_text(NMAP_ENRICHMENT_XML)
        output = io.StringIO()

        with (
            patch("sys.argv", ["hylianscan", "example.com", "-p", "80", "--nmap", "--quiet"]),
            patch("sys.stdout", output),
            patch("hylianscan.resolve_target", return_value=make_target()),
            patch("hylianscan.run_port_scan", return_value=scan_result),
            patch(
                "hylianscan.run_nmap_service_version_scan",
                return_value=import_result,
            ) as nmap_runner,
        ):
            hylianscan.main()

        nmap_runner.assert_called_once_with("127.0.0.1", [80])
        self.assertIn("Nmap Enrichment", output.getvalue())
        self.assertIn("80/tcp", output.getvalue())

    def test_main_passes_custom_nmap_path_to_runner(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = parse_nmap_xml_text(NMAP_ENRICHMENT_XML)

        with (
            patch(
                "sys.argv",
                [
                    "hylianscan",
                    "example.com",
                    "-p",
                    "80",
                    "--nmap",
                    "--nmap-path",
                    "/usr/bin/nmap",
                    "--quiet",
                ],
            ),
            patch("sys.stdout", io.StringIO()),
            patch("hylianscan.resolve_target", return_value=make_target()),
            patch("hylianscan.run_port_scan", return_value=scan_result),
            patch(
                "hylianscan.run_nmap_service_version_scan",
                return_value=import_result,
            ) as nmap_runner,
        ):
            hylianscan.main()

        nmap_runner.assert_called_once_with(
            "127.0.0.1",
            [80],
            nmap_binary="/usr/bin/nmap",
        )

    def test_main_skips_nmap_when_native_scan_finds_no_open_ports(self) -> None:
        scan_result = make_scan_result(())
        output = io.StringIO()

        with (
            patch("sys.argv", ["hylianscan", "example.com", "-p", "80", "--nmap", "--quiet"]),
            patch("sys.stdout", output),
            patch("hylianscan.resolve_target", return_value=make_target()),
            patch("hylianscan.run_port_scan", return_value=scan_result),
            patch("hylianscan.run_nmap_service_version_scan") as nmap_runner,
        ):
            hylianscan.main()

        nmap_runner.assert_not_called()
        self.assertIn(
            "Nmap enrichment skipped: no open TCP ports found.",
            output.getvalue(),
        )

    def test_main_prints_warning_when_nmap_runner_fails(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        output = io.StringIO()

        with (
            patch("sys.argv", ["hylianscan", "example.com", "-p", "80", "--nmap", "--quiet"]),
            patch("sys.stdout", output),
            patch("hylianscan.resolve_target", return_value=make_target()),
            patch("hylianscan.run_port_scan", return_value=scan_result),
            patch(
                "hylianscan.run_nmap_service_version_scan",
                side_effect=RuntimeError("Nmap binary not found: nmap."),
            ),
        ):
            hylianscan.main()

        self.assertIn(
            "Nmap enrichment skipped: Nmap binary not found: nmap.",
            output.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
