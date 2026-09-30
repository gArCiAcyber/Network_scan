"""Tests for optional live Nmap service scan orchestration."""

import io
import json
from dataclasses import replace
from pathlib import Path
import re
import socket
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import Mock, call, patch

import hylianscan
from core.colors import BRIGHT_WHITE, RESET
from core.nmap_live_display import (
    NMAP_ASCII_SPINNER_FRAMES,
    NMAP_BRAILLE_SPINNER_FRAMES,
    NmapServiceScanDisplay,
    select_spinner_frames,
)
from modules.nmap_enrichment import (
    build_completed_nmap_enrichment,
    build_failed_nmap_enrichment,
    build_multi_nmap_enrichment,
    format_nmap_enrichment_skipped,
    format_nmap_enrichment_summary,
)
from modules.nmap_xml import parse_nmap_xml_text
from modules.target import ResolvedAddress, TargetInfo
from modules.tcp_scanner import PortScanResult, ScanResult


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


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
<runstats><finished exit="success"/></runstats></nmaprun>
"""


def strip_ansi(value: str) -> str:
    """Remove ANSI escape codes from captured terminal output."""
    return ANSI_PATTERN.sub("", value)


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


def make_import_for_scope(target, ports):
    root = ET.fromstring(NMAP_ENRICHMENT_XML)
    root.find("host/address").set("addr", target)
    root.find("host/ports").clear()
    for port in ports:
        element = ET.SubElement(root.find("host/ports"), "port", protocol="tcp", portid=str(port))
        ET.SubElement(element, "state", state="open")
        ET.SubElement(element, "service", name="http", product="nginx", version="1.24", method="probed", conf="10")
    return parse_nmap_xml_text(ET.tostring(root, encoding="unicode"))


class NmapEnrichmentFormattingTests(unittest.TestCase):
    """Validate terminal formatting for live Nmap service scan output."""

    def test_failed_status_survives_narrow_wrapping_with_partial_evidence(self) -> None:
        error = RuntimeError("time limit reached")
        error.execution = {"status": "timed_out", "stdout": NMAP_ENRICHMENT_XML,
                           "stderr": "WARNING: Could not import all necessary Npcap functions."}
        with patch("core.terminal.shutil.get_terminal_size") as size:
            size.return_value.columns = 24
            result = build_failed_nmap_enrichment(error, "127.0.0.1", [80, 31337])
        self.assertIsNotNone(result.import_result)
        self.assertEqual(result.terminal_text.count("Nmap service scan"), 1)
        self.assertIn("timed_out", result.terminal_text)
        self.assertNotIn("completed", result.terminal_text)
        self.assertRegex(result.terminal_text, r"Npcap functions\s+unavailable")

    def test_summary_includes_status_target_ports_and_service_details(self) -> None:
        import_result = parse_nmap_xml_text(NMAP_ENRICHMENT_XML)
        summary = format_nmap_enrichment_summary(import_result, "127.0.0.1", [80])

        self.assertIn("Nmap service scan", summary)
        self.assertIn("Target          : 127.0.0.1", summary)
        self.assertIn("Ports scanned   : 80", summary)
        self.assertIn("Status          : completed", summary)
        self.assertIn("80/tcp", summary)
        self.assertIn("open", summary)
        self.assertIn("http", summary)
        self.assertIn("nginx 1.24", summary)
        self.assertIn("31337/tcp", summary)
        self.assertIn("tcpwrapped", summary)
        self.assertNotIn("method=", summary)
        self.assertNotIn("confidence=", summary)
        self.assertIn("PORT       STATE  SERVICE   VERSION", summary)
        self.assertNotIn("SOURCE", summary)
        self.assertNotIn("probed", summary)

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

        self.assertIn("Nmap service scan", summary)
        self.assertIn("Target          : 127.0.0.1", summary)
        self.assertIn("Ports scanned   : none", summary)
        self.assertIn("Status          : skipped", summary)
        self.assertIn("Reason: no open TCP ports found.", summary)
        self.assertNotIn("method=", summary)
        self.assertNotIn("confidence=", summary)
        self.assertNotIn("PORT       STATE", summary)

    def test_multi_address_summary_shows_npcap_notice_once_and_keeps_raw_stderr(self) -> None:
        warning = ("WARNING: Could not import all necessary Npcap functions. "
                   "Resorting to connect() mode -- Nmap may not function completely")
        runs = []
        for address in ("192.0.2.10", "198.51.100.20"):
            parsed = replace(make_import_for_scope(address, [443]),
                             execution={"status": "completed", "stderr": warning})
            runs.append(build_completed_nmap_enrichment(parsed, address, [443],
                        elapsed_seconds=1.25, timeout_seconds=120.0))
        summary = build_multi_nmap_enrichment("example.com", runs).terminal_text
        self.assertEqual(summary.count("Nmap service scan"), 1)
        self.assertEqual(summary.count("Notice: Npcap functions unavailable"), 1)
        self.assertNotIn("Could not import all necessary", summary)
        self.assertIn("Deadline: 120s/address", summary)
        self.assertIn("1.25s", summary)
        self.assertEqual(runs[0].execution["stderr"], warning)


class NmapEnrichmentMainTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        patcher = patch("core.output.resolve_output_dir", return_value=Path(directory.name))
        patcher.start()
        self.addCleanup(patcher.stop)

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
        import_result = make_import_for_scope("127.0.0.1", [80])
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
        self.assertIn("Nmap service scan", output.getvalue())
        self.assertIn("80/tcp", output.getvalue())
        self.assertNotIn("method=", output.getvalue())
        self.assertNotIn("confidence=", output.getvalue())
        self.assertNotIn("Starting Nmap Service Scan", output.getvalue())
        self.assertNotIn("Running Nmap service/version detection", output.getvalue())
        self.assertNotIn("Nmap Enrichment", output.getvalue())

    def test_main_runs_and_reports_nmap_once_per_concrete_address(self) -> None:
        addresses = (
            ResolvedAddress("192.0.2.10", socket.AF_INET),
            ResolvedAddress("198.51.100.20", socket.AF_INET),
        )
        target = TargetInfo(
            raw_input="example.com",
            target_host="example.com",
            resolved_ip=addresses[0].address,
            is_ip_address=False,
            addresses=addresses,
        )
        scan_result = ScanResult(
            target_host="example.com",
            resolved_ip=addresses[0].address,
            scanned_ports=3,
            open_ports=(
                PortScanResult(
                    port=80,
                    service="http",
                    banner=None,
                    response_time=0.01,
                    address=addresses[0].address,
                    address_family="ipv4",
                ),
                PortScanResult(
                    port=443,
                    service="https",
                    banner=None,
                    response_time=0.01,
                    address=addresses[1].address,
                    address_family="ipv4",
                ),
                PortScanResult(
                    port=8080,
                    service="http-alt",
                    banner=None,
                    response_time=0.01,
                    address=addresses[0].address,
                    address_family="ipv4",
                ),
            ),
            duration=0.02,
            resolved_ips=tuple(address.address for address in addresses),
            address_family="ipv4",
            addresses=addresses,
        )
        import_result = make_import_for_scope("127.0.0.1", [80])
        output = io.StringIO()

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
                        "80,443,8080",
                        "--nmap",
                        "-mc",
                        "404",
                        "-o",
                        "--json-output",
                        "--quiet",
                    ],
                ),
                patch("sys.stdout", output),
                patch("hylianscan.resolve_target", return_value=target),
                patch("hylianscan.run_port_scan", return_value=scan_result),
                patch("hylianscan.resolve_output_path", return_value=txt_output_path),
                patch(
                    "hylianscan.resolve_json_output_path",
                    return_value=json_output_path,
                ),
                patch(
                    "hylianscan.run_nmap_service_version_scan",
                    side_effect=make_import_for_scope,
                ) as nmap_runner,
            ):
                hylianscan.main()

            saved_report = txt_output_path.read_text(encoding="utf-8")
            document = json.loads(json_output_path.read_text(encoding="utf-8"))

        self.assertEqual(
            nmap_runner.call_args_list,
            [
                call("192.0.2.10", [80, 8080]),
                call("198.51.100.20", [443]),
            ],
        )
        self.assertEqual(output.getvalue().count("Nmap service scan"), 1)
        self.assertEqual(saved_report.count("Nmap service scan"), 1)
        self.assertIn("192.0.2.10", saved_report)
        self.assertIn("198.51.100.20", saved_report)
        self.assertIn("Time: native", saved_report)
        self.assertIn("0 shown, 3 hidden", output.getvalue())
        self.assertEqual(document["schema"]["version"], 2)
        nmap = document["enrichment"]["nmap"]
        self.assertEqual(nmap["status"], "completed")
        self.assertEqual(nmap["target"], "example.com")
        self.assertEqual(nmap["ports_requested"], [80, 443, 8080])
        self.assertEqual(
            [(run["target"], run["ports_requested"]) for run in nmap["runs"]],
            [("192.0.2.10", [80, 8080]), ("198.51.100.20", [443])],
        )
        self.assertEqual(
            document["scan"]["report_filters"]["http_status_codes"],
            {
                "expression": "404",
                "resolved_codes": [404],
                "native_open_ports": 3,
                "shown_open_ports": 0,
                "hidden_open_ports": 3,
            },
        )

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

    def test_live_display_follows_each_address_and_stops_on_failure_or_interruption(self) -> None:
        addresses = ("192.0.2.10", "fe80::1%4")
        scan_result = make_scan_result((
            replace(make_open_port(80), address=addresses[0]),
            replace(make_open_port(443), address="fe80::1", scope_id=4),
        ))
        for error in (None, RuntimeError("Nmap unavailable"), KeyboardInterrupt()):
            with self.subTest(error=error):
                events = []
                displays = [Mock(), Mock()]
                for address, display in zip(addresses, displays):
                    display.start.side_effect = lambda address=address: events.append(("start", address))
                    display.stop.side_effect = lambda address=address: events.append(("stop", address))

                def run(address, ports):
                    events.append(("run", address, ports))
                    if error is not None and address == addresses[-1]:
                        raise error
                    return make_import_for_scope(address, ports)

                with patch("hylianscan.NmapServiceScanDisplay", side_effect=displays) as factory, \
                     patch("hylianscan.run_nmap_service_version_scan", side_effect=run):
                    result = hylianscan.run_live_nmap_enrichment(make_target(), scan_result, quiet=False)
                self.assertEqual(factory.call_args_list, [call(addresses[0], [80]), call(addresses[1], [443])])
                self.assertEqual(events, [
                    ("start", addresses[0]), ("run", addresses[0], [80]), ("stop", addresses[0]),
                    ("start", addresses[1]), ("run", addresses[1], [443]), ("stop", addresses[1]),
                ])
                self.assertEqual(result.status, "completed" if error is None else
                                 "interrupted" if isinstance(error, KeyboardInterrupt) else "partial")

    def test_nmap_spinner_fits_narrow_terminal(self) -> None:
        display = NmapServiceScanDisplay("127.0.0.1", [80])
        with patch("core.nmap_live_display.shutil.get_terminal_size") as size, \
             patch("core.nmap_live_display.write_dynamic_line") as render:
            size.return_value.columns = 24
            display._write_spinner_frame()
        line = strip_ansi(render.call_args.args[0])
        self.assertLess(len(line), 24)
        self.assertIn("Nmap", line)

    def test_main_shows_live_nmap_progress_before_final_block(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = make_import_for_scope("127.0.0.1", [80])
        output = io.StringIO()

        with (
            patch("sys.argv", ["hylianscan", "example.com", "-p", "80", "--nmap"]),
            patch("sys.stdout", output),
            patch("hylianscan.clear_screen"),
            patch("hylianscan.show_banner"),
            patch(
                "core.nmap_live_display.select_spinner_frames",
                return_value=NMAP_BRAILLE_SPINNER_FRAMES,
            ),
            patch("hylianscan.resolve_target", return_value=make_target()),
            patch("hylianscan.run_port_scan", return_value=scan_result),
            patch(
                "hylianscan.run_nmap_service_version_scan",
                return_value=import_result,
            ) as nmap_runner,
        ):
            hylianscan.main()

        terminal_output = output.getvalue()
        clean_output = strip_ansi(terminal_output)
        nmap_runner.assert_called_once_with("127.0.0.1", [80])
        self.assertNotIn("Starting Nmap Service Scan", terminal_output)
        self.assertNotIn("Target : 127.0.0.1", terminal_output)
        self.assertNotIn("Ports  : 80", terminal_output)
        self.assertIn("Running Nmap service/version detection", terminal_output)
        self.assertIn(
            f"{BRIGHT_WHITE}⠋{RESET} Running Nmap service/version detection",
            terminal_output,
        )
        self.assertIn("-> Nmap service/version detection", clean_output)
        self.assertIn("Target          : 127.0.0.1", clean_output)
        self.assertIn("Ports scanned   : 80", clean_output)
        self.assertIn("Status          : running", clean_output)
        self.assertNotIn("Running Nmap service/version detection... |", terminal_output)
        self.assertEqual(terminal_output.count("[+] NMAP SERVICE SCAN"), 1)
        self.assertLess(clean_output.index("Native scan: completed"),
                        clean_output.index("[*] Nmap Service/Version Detection"))
        self.assertLess(
            clean_output.index("Running Nmap service/version detection"),
            clean_output.index("TRIFORCE"),
        )
        self.assertNotIn("method=", terminal_output)
        self.assertNotIn("confidence=", terminal_output)

    def test_main_passes_custom_nmap_path_to_runner(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = make_import_for_scope("127.0.0.1", [80])

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
                    "--nmap-timeout",
                    "120",
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
            timeout=120.0,
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
            "Reason: no open TCP ports found.",
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
            "Reason: Nmap binary not found: nmap.",
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

        self.assertIn("Nmap service scan", output.getvalue())
        self.assertIn("Status          : failed", output.getvalue())
        self.assertIn("requires exactly one up host", output.getvalue())

    def test_main_saves_nmap_enrichment_in_tcp_txt_report(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = make_import_for_scope("127.0.0.1", [80])

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
            self.assertIn("Hylianscan scan report for example.com", saved_report)
            self.assertIn("Nmap service scan", saved_report)
            self.assertIn("Status          : completed", saved_report)
            self.assertIn("80/tcp", saved_report)
            self.assertNotIn("method=", saved_report)
            self.assertNotIn("confidence=", saved_report)
            self.assertNotIn("Starting Nmap Service Scan", saved_report)
            self.assertNotIn("Target : 127.0.0.1", saved_report)
            self.assertNotIn("Ports  : 80", saved_report)
            self.assertNotIn("Running Nmap service/version detection", saved_report)
            self.assertNotIn("Nmap Enrichment", saved_report)
            self.assertNotIn("\x1b[", saved_report)

    def test_match_code_with_nmap_keeps_native_evidence_in_quiet_txt(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = make_import_for_scope("127.0.0.1", [80])
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as temporary_dir:
            txt_output_path = Path(temporary_dir) / "tcp_report.txt"

            with (
                patch(
                    "sys.argv",
                    [
                        "hylianscan",
                        "example.com",
                        "-p",
                        "80",
                        "--nmap",
                        "-mc",
                        "404",
                        "-o",
                        "--quiet",
                    ],
                ),
                patch("sys.stdout", output),
                patch("hylianscan.resolve_target", return_value=make_target()),
                patch("hylianscan.run_port_scan", return_value=scan_result),
                patch("hylianscan.resolve_output_path", return_value=txt_output_path),
                patch("hylianscan.resolve_json_output_path", return_value=None),
                patch(
                    "hylianscan.run_nmap_service_version_scan",
                    return_value=import_result,
                ) as nmap_runner,
            ):
                hylianscan.main()

            terminal_output = output.getvalue()
            saved_report = txt_output_path.read_text(encoding="utf-8")

        nmap_runner.assert_called_once_with("127.0.0.1", [80])
        self.assertIsNone(ANSI_PATTERN.search(terminal_output))
        self.assertIn("HTTP filter: 404", terminal_output)
        self.assertIn("0 shown, 1 hidden", terminal_output)
        self.assertIn(
            "No open findings matched the HTTP filter.",
            terminal_output,
        )
        self.assertNotIn("No open ports found", terminal_output)
        self.assertEqual(terminal_output.count("Nmap service scan"), 1)
        self.assertIn("HTTP filter: 404 (report only)", saved_report)
        self.assertEqual(saved_report.count("Nmap service scan"), 1)

    def test_main_saves_nmap_enrichment_in_tcp_json_report(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = make_import_for_scope("127.0.0.1", [80])

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
            self.assertEqual(nmap["ports_returned"], [80])
            self.assertEqual(nmap["results"][0]["service"]["name"], "http")

    def test_main_saves_nmap_enrichment_in_both_reports(self) -> None:
        scan_result = make_scan_result((make_open_port(),))
        import_result = make_import_for_scope("127.0.0.1", [80])

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
                "Nmap service scan",
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
                "Reason: no open TCP ports found.",
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
                "Reason: Nmap binary not found: nmap.",
                saved_report,
            )
            nmap = json.loads(
                json_output_path.read_text(encoding="utf-8")
            )["enrichment"]["nmap"]
            self.assertEqual(nmap["status"], "failed")
            self.assertEqual(nmap["reason"], "Nmap binary not found: nmap.")
            self.assertEqual(nmap["ports_requested"], [80])


if __name__ == "__main__":
    unittest.main()
