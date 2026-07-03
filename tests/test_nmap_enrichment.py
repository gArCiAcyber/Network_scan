"""Tests for optional live Nmap service scan orchestration."""

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hylianscan
from core.nmap_live_display import (
    NMAP_ASCII_SPINNER_FRAMES,
    NMAP_BRAILLE_SPINNER_FRAMES,
    NmapServiceScanDisplay,
    select_spinner_frames,
)
from modules.nmap_enrichment import (
    format_nmap_enrichment_skipped,
    format_nmap_enrichment_summary,
)
from modules.nmap_xml import parse_nmap_xml_text
from modules.target import TargetInfo
from modules.tcp_scanner import PortScanResult, ScanResult


NMAP_ENRICHMENT_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV -Pn -n -p 80,31337 -oX - 127.0.0.1"
         start="1710000000" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="31337">
        <state state="open"/>
        <service name="tcpwrapped" method="probed" conf="8"/>
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
    """Validate terminal formatting for live Nmap service scan output."""

    def test_summary_includes_status_target_ports_and_service_details(self) -> None:
        import_result = parse_nmap_xml_text(NMAP_ENRICHMENT_XML)
        summary = format_nmap_enrichment_summary(import_result, "127.0.0.1", [80])

        self.assertIn("[+] NMAP SERVICE SCAN", summary)
        self.assertIn("Status          : completed", summary)
        self.assertIn("Target          : 127.0.0.1", summary)
        self.assertIn("Ports scanned   : 80", summary)
        self.assertIn("PORT", summary)
        self.assertIn("STATE", summary)
        self.assertIn("SERVICE", summary)
        self.assertIn("VERSION", summary)
        self.assertIn("80/tcp", summary)
        self.assertIn("open", summary)
        self.assertIn("http", summary)
        self.assertIn("nginx 1.24", summary)
        self.assertIn("31337/tcp", summary)
        self.assertIn("tcpwrapped", summary)
        self.assertNotIn("method=", summary)
        self.assertNotIn("confidence=", summary)
        self.assertNotIn("Nmap Enrichment", summary)

    def test_summary_sorts_and_deduplicates_requested_ports(self) -> None:
        import_result = parse_nmap_xml_text(NMAP_ENRICHMENT_XML)
        summary = format_nmap_enrichment_summary(
            import_result,
            "127.0.0.1",
            [443, 80, 80],
        )

        self.assertIn("Ports scanned   : 80,443", summary)

    def test_skipped_message_uses_standard_prefix(self) -> None:
        summary = format_nmap_enrichment_skipped(
            "no open TCP ports found.",
            "127.0.0.1",
            [],
        )

        self.assertIn("[+] NMAP SERVICE SCAN", summary)
        self.assertIn("Target          : 127.0.0.1", summary)
        self.assertIn("Ports scanned   : none", summary)
        self.assertIn("Status          : skipped", summary)
        self.assertIn("Reason          : no open TCP ports found.", summary)
        self.assertNotIn("method=", summary)
        self.assertNotIn("confidence=", summary)
        self.assertNotIn("Nmap Enrichment", summary)


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
        self.assertIn("[+] NMAP SERVICE SCAN", output.getvalue())
        self.assertIn("80/tcp", output.getvalue())
        self.assertNotIn("method=", output.getvalue())
        self.assertNotIn("confidence=", output.getvalue())
        self.assertNotIn("Starting Nmap Service Scan", output.getvalue())
        self.assertNotIn("Running Nmap service/version detection", output.getvalue())
        self.assertNotIn("Nmap Enrichment", output.getvalue())

    def test_nmap_display_uses_braille_spinner_when_encoding_supports_it(self) -> None:
        self.assertEqual(select_spinner_frames("utf-8"), NMAP_BRAILLE_SPINNER_FRAMES)

    def test_nmap_display_falls_back_to_ascii_when_braille_is_not_supported(self) -> None:
        self.assertEqual(select_spinner_frames("ascii"), NMAP_ASCII_SPINNER_FRAMES)

    def test_nmap_dynamic_line_starts_with_spinner_frame(self) -> None:
        with patch(
            "core.nmap_live_display.select_spinner_frames",
            return_value=NMAP_BRAILLE_SPINNER_FRAMES,
        ):
            display = NmapServiceScanDisplay("127.0.0.1", [80])

        with patch("core.nmap_live_display.write_dynamic_line") as write_dynamic_line:
            display._write_spinner_frame()

        dynamic_line = write_dynamic_line.call_args.args[0]
        self.assertIn("⠋", dynamic_line)
        self.assertLess(
            dynamic_line.index("⠋"),
            dynamic_line.index("Running Nmap service/version detection"),
        )
        self.assertNotIn("Running Nmap service/version detection... |", dynamic_line)

    def test_main_shows_live_nmap_progress_before_final_block(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = parse_nmap_xml_text(NMAP_ENRICHMENT_XML)
        output = io.StringIO()

        with (
            patch("sys.argv", ["hylianscan", "example.com", "-p", "80", "--nmap"]),
            patch("sys.stdout", output),
            patch("hylianscan.clear_screen"),
            patch("hylianscan.show_banner"),
            patch("hylianscan.resolve_target", return_value=make_target()),
            patch("hylianscan.run_port_scan", return_value=scan_result),
            patch(
                "hylianscan.run_nmap_service_version_scan",
                return_value=import_result,
            ) as nmap_runner,
        ):
            hylianscan.main()

        terminal_output = output.getvalue()
        nmap_runner.assert_called_once_with("127.0.0.1", [80])
        self.assertIn("Starting Nmap Service Scan", terminal_output)
        self.assertIn("Target : 127.0.0.1", terminal_output)
        self.assertIn("Ports  : 80", terminal_output)
        self.assertIn("Running Nmap service/version detection", terminal_output)
        self.assertNotIn("Running Nmap service/version detection... |", terminal_output)
        self.assertEqual(terminal_output.count("[+] NMAP SERVICE SCAN"), 1)
        self.assertNotIn("method=", terminal_output)
        self.assertNotIn("confidence=", terminal_output)

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
            "Reason          : no open TCP ports found.",
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
            "Reason          : Nmap binary not found: nmap.",
            output.getvalue(),
        )

    def test_main_prints_warning_when_nmap_summary_formatting_fails(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = parse_nmap_xml_text("<nmaprun scanner='nmap'/>")
        output = io.StringIO()

        with (
            patch("sys.argv", ["hylianscan", "example.com", "-p", "80", "--nmap", "--quiet"]),
            patch("sys.stdout", output),
            patch("hylianscan.resolve_target", return_value=make_target()),
            patch("hylianscan.run_port_scan", return_value=scan_result),
            patch("hylianscan.run_nmap_service_version_scan", return_value=import_result),
        ):
            hylianscan.main()

        self.assertIn("[+] NMAP SERVICE SCAN", output.getvalue())
        self.assertIn("Status          : skipped", output.getvalue())
        self.assertIn("requires exactly one up host", output.getvalue())

    def test_main_saves_nmap_enrichment_in_tcp_txt_report(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = parse_nmap_xml_text(NMAP_ENRICHMENT_XML)

        with tempfile.TemporaryDirectory() as temporary_dir:
            txt_output_path = Path(temporary_dir) / "tcp_report.txt"

            with (
                patch(
                    "sys.argv",
                    ["hylianscan", "example.com", "-p", "80", "--nmap", "-o", "--quiet"],
                ),
                patch("sys.stdout", io.StringIO()),
                patch("hylianscan.resolve_target", return_value=make_target()),
                patch("hylianscan.run_port_scan", return_value=scan_result),
                patch("hylianscan.resolve_output_path", return_value=txt_output_path),
                patch("hylianscan.resolve_json_output_path", return_value=None),
                patch(
                    "hylianscan.run_nmap_service_version_scan",
                    return_value=import_result,
                ),
            ):
                hylianscan.main()

            saved_report = txt_output_path.read_text(encoding="utf-8")
            self.assertIn("Target: example.com", saved_report)
            self.assertIn("[+] NMAP SERVICE SCAN", saved_report)
            self.assertIn("Status          : completed", saved_report)
            self.assertIn("80/tcp", saved_report)
            self.assertNotIn("method=", saved_report)
            self.assertNotIn("confidence=", saved_report)
            self.assertNotIn("Starting Nmap Service Scan", saved_report)
            self.assertNotIn("Running Nmap service/version detection", saved_report)
            self.assertNotIn("Nmap Enrichment", saved_report)
            self.assertNotIn("\x1b[", saved_report)

    def test_main_saves_nmap_enrichment_in_tcp_json_report(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = parse_nmap_xml_text(NMAP_ENRICHMENT_XML)

        with tempfile.TemporaryDirectory() as temporary_dir:
            json_output_path = Path(temporary_dir) / "tcp_results.json"

            with (
                patch(
                    "sys.argv",
                    [
                        "hylianscan",
                        "example.com",
                        "-p",
                        "80",
                        "--nmap",
                        "--json-output",
                        "--quiet",
                    ],
                ),
                patch("sys.stdout", io.StringIO()),
                patch("hylianscan.resolve_target", return_value=make_target()),
                patch("hylianscan.run_port_scan", return_value=scan_result),
                patch("hylianscan.resolve_output_path", return_value=None),
                patch("hylianscan.resolve_json_output_path", return_value=json_output_path),
                patch(
                    "hylianscan.run_nmap_service_version_scan",
                    return_value=import_result,
                ),
            ):
                hylianscan.main()

            document = json.loads(json_output_path.read_text(encoding="utf-8"))
            nmap = document["enrichment"]["nmap"]
            self.assertEqual(nmap["status"], "completed")
            self.assertEqual(nmap["target"], "127.0.0.1")
            self.assertEqual(nmap["ports_requested"], [80])
            self.assertEqual(nmap["ports_returned"], [80, 31337])
            self.assertEqual(nmap["results"][0]["service"]["name"], "http")
            self.assertEqual(nmap["results"][1]["service"]["name"], "tcpwrapped")
            self.assertEqual(nmap["results"][1]["service"]["method"], "probed")
            self.assertEqual(nmap["results"][1]["service"]["conf"], 8)

    def test_main_saves_nmap_enrichment_in_both_reports(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = parse_nmap_xml_text(NMAP_ENRICHMENT_XML)

        with tempfile.TemporaryDirectory() as temporary_dir:
            txt_output_path = Path(temporary_dir) / "tcp_report.txt"
            json_output_path = Path(temporary_dir) / "tcp_results.json"

            with (
                patch(
                    "sys.argv",
                    [
                        "hylianscan",
                        "example.com",
                        "-p",
                        "80",
                        "--nmap",
                        "-o",
                        "--json-output",
                        "--quiet",
                    ],
                ),
                patch("sys.stdout", io.StringIO()),
                patch("hylianscan.resolve_target", return_value=make_target()),
                patch("hylianscan.run_port_scan", return_value=scan_result),
                patch("hylianscan.resolve_output_path", return_value=txt_output_path),
                patch("hylianscan.resolve_json_output_path", return_value=json_output_path),
                patch(
                    "hylianscan.run_nmap_service_version_scan",
                    return_value=import_result,
                ),
            ):
                hylianscan.main()

            self.assertTrue(txt_output_path.exists())
            self.assertTrue(json_output_path.exists())
            self.assertIn(
                "[+] NMAP SERVICE SCAN",
                txt_output_path.read_text(encoding="utf-8"),
            )
            self.assertIn(
                "enrichment",
                json.loads(json_output_path.read_text(encoding="utf-8")),
            )

    def test_main_saves_skipped_nmap_enrichment_when_no_ports_are_open(self) -> None:
        scan_result = make_scan_result(())

        with tempfile.TemporaryDirectory() as temporary_dir:
            txt_output_path = Path(temporary_dir) / "tcp_report.txt"
            json_output_path = Path(temporary_dir) / "tcp_results.json"

            with (
                patch(
                    "sys.argv",
                    [
                        "hylianscan",
                        "example.com",
                        "-p",
                        "80",
                        "--nmap",
                        "-o",
                        "--json-output",
                        "--quiet",
                    ],
                ),
                patch("sys.stdout", io.StringIO()),
                patch("hylianscan.resolve_target", return_value=make_target()),
                patch("hylianscan.run_port_scan", return_value=scan_result),
                patch("hylianscan.resolve_output_path", return_value=txt_output_path),
                patch("hylianscan.resolve_json_output_path", return_value=json_output_path),
                patch("hylianscan.run_nmap_service_version_scan") as nmap_runner,
            ):
                hylianscan.main()

            nmap_runner.assert_not_called()
            saved_report = txt_output_path.read_text(encoding="utf-8")
            self.assertIn(
                "Reason          : no open TCP ports found.",
                saved_report,
            )
            nmap = json.loads(
                json_output_path.read_text(encoding="utf-8")
            )["enrichment"]["nmap"]
            self.assertEqual(nmap["status"], "skipped")
            self.assertEqual(nmap["reason"], "no open TCP ports found.")
            self.assertEqual(nmap["ports_requested"], [])

    def test_main_saves_skipped_nmap_enrichment_when_runner_fails(self) -> None:
        scan_result = make_scan_result((make_open_port(),))

        with tempfile.TemporaryDirectory() as temporary_dir:
            txt_output_path = Path(temporary_dir) / "tcp_report.txt"
            json_output_path = Path(temporary_dir) / "tcp_results.json"

            with (
                patch(
                    "sys.argv",
                    [
                        "hylianscan",
                        "example.com",
                        "-p",
                        "80",
                        "--nmap",
                        "-o",
                        "--json-output",
                        "--quiet",
                    ],
                ),
                patch("sys.stdout", io.StringIO()),
                patch("hylianscan.resolve_target", return_value=make_target()),
                patch("hylianscan.run_port_scan", return_value=scan_result),
                patch("hylianscan.resolve_output_path", return_value=txt_output_path),
                patch("hylianscan.resolve_json_output_path", return_value=json_output_path),
                patch(
                    "hylianscan.run_nmap_service_version_scan",
                    side_effect=RuntimeError("Nmap binary not found: nmap."),
                ),
            ):
                hylianscan.main()

            saved_report = txt_output_path.read_text(encoding="utf-8")
            self.assertIn(
                "Reason          : Nmap binary not found: nmap.",
                saved_report,
            )
            nmap = json.loads(
                json_output_path.read_text(encoding="utf-8")
            )["enrichment"]["nmap"]
            self.assertEqual(nmap["status"], "skipped")
            self.assertEqual(nmap["reason"], "Nmap binary not found: nmap.")
            self.assertEqual(nmap["ports_requested"], [80])


if __name__ == "__main__":
    unittest.main()
