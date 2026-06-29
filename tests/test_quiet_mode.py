"""Tests for quiet-mode orchestration behavior."""

import argparse
import io
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import hylianscan
from core.output import DEFAULT_TCP_TEXT_ARGUMENT
from core.panel import build_quiet_final_panel
from modules.target import TargetInfo
from modules.tcp_scanner import PortScanResult, ScanResult


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


class QuietModeTests(unittest.TestCase):
    """Validate quiet mode suppresses live rendering hooks."""

    def test_quiet_tcp_summary_is_plain_text_without_decorative_panel(self) -> None:
        scan_result = ScanResult(
            target_host="example.com",
            resolved_ip="93.184.216.34",
            scanned_ports=2,
            open_ports=(
                PortScanResult(
                    port=80,
                    service="HTTP",
                    banner="HTTP/1.1 200 OK Server: hylianscan-mock",
                    response_time=0.01,
                ),
            ),
            duration=1.23,
        )

        output = build_quiet_final_panel(scan_result, scan_scope="Custom Port List")

        self.assertIsNone(ANSI_PATTERN.search(output))
        self.assertNotIn("TRIFORCE", output)
        self.assertNotIn("SCAN POWERED", output)
        self.assertNotIn("------------------------------------------------------------------------", output)
        self.assertIn("Target: example.com", output)
        self.assertIn("Resolved IP: 93.184.216.34", output)
        self.assertIn("Scan Scope: Custom Port List", output)
        self.assertIn("Total Scan Time: 1.23s", output)
        self.assertIn("Open Ports:", output)
        self.assertIn("- 80/tcp open http 200 OK", output)

    def test_quiet_tcp_summary_reports_no_open_ports_plainly(self) -> None:
        scan_result = ScanResult(
            target_host="example.com",
            resolved_ip="93.184.216.34",
            scanned_ports=2,
            open_ports=(),
            duration=1.23,
        )

        output = build_quiet_final_panel(scan_result)

        self.assertIsNone(ANSI_PATTERN.search(output))
        self.assertIn("No open ports found.", output)
        self.assertNotIn("TRIFORCE", output)
        self.assertNotIn("------------------------------------------------------------------------", output)

    def test_quiet_tcp_summary_does_not_include_orientation_configuration(self) -> None:
        scan_result = ScanResult(
            target_host="example.com",
            resolved_ip="93.184.216.34",
            scanned_ports=2,
            open_ports=(),
            duration=1.23,
        )

        output = build_quiet_final_panel(scan_result)

        self.assertNotIn("Target Orientation", output)
        self.assertNotIn("Stance", output)
        self.assertNotIn("Workers", output)
        self.assertNotIn("Timeout", output)
        self.assertNotIn("Max Rate", output)
        self.assertNotIn("Config Source", output)

    def test_quiet_tcp_summary_keeps_port_profile_scope_plain(self) -> None:
        scan_result = ScanResult(
            target_host="example.com",
            resolved_ip="93.184.216.34",
            scanned_ports=2,
            open_ports=(),
            duration=1.23,
        )

        output = build_quiet_final_panel(
            scan_result,
            scan_scope="Port Profile: web / sheikah",
        )

        self.assertIsNone(ANSI_PATTERN.search(output))
        self.assertIn("Scan Scope: Port Profile: web / sheikah", output)
        self.assertNotIn("Port Profile  :", output)

    def test_run_port_scan_quiet_disables_live_callbacks(self) -> None:
        target = TargetInfo(
            raw_input="127.0.0.1",
            target_host="127.0.0.1",
            resolved_ip="127.0.0.1",
            is_ip_address=True,
        )
        scan_result = ScanResult(
            target_host=target.target_host,
            resolved_ip=target.resolved_ip,
            scanned_ports=1,
            open_ports=(),
            duration=0.01,
        )

        with patch("hylianscan.scan_tcp_ports", return_value=scan_result) as scanner:
            result = hylianscan.run_port_scan(
                target=target,
                ports_to_scan=[80],
                timeout=1.0,
                max_workers=1,
                quiet=True,
            )

        self.assertIs(result, scan_result)
        call_kwargs = scanner.call_args.kwargs
        self.assertIsNone(call_kwargs["progress_callback"])
        self.assertIsNone(call_kwargs["open_port_callback"])
        self.assertIsNone(call_kwargs["service_probe_start_callback"])
        self.assertIsNone(call_kwargs["service_probe_complete_callback"])
        self.assertIsNone(call_kwargs["max_rate"])

    def test_main_quiet_mode_validation_errors_are_plain_text(self) -> None:
        args = argparse.Namespace(
            ports=None,
            top_ports=None,
            port_profile="web",
            subfinder=True,
            amass=False,
            quiet=True,
        )

        output = io.StringIO()
        with patch("hylianscan.parse_arguments", return_value=args), redirect_stdout(output):
            hylianscan.main()

        rendered = output.getvalue()

        self.assertIsNone(ANSI_PATTERN.search(rendered))
        self.assertIn("Error: Use passive discovery provider flags", rendered)

    def test_main_quiet_tcp_workspace_output_does_not_print_saved_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            workspace_dir = Path(temporary_dir) / "example.com" / "20260616_120000"
            target = TargetInfo(
                raw_input="example.com",
                target_host="example.com",
                resolved_ip="93.184.216.34",
                is_ip_address=False,
            )
            scan_result = ScanResult(
                target_host=target.target_host,
                resolved_ip=target.resolved_ip,
                scanned_ports=1,
                open_ports=(),
                duration=0.01,
            )
            args = argparse.Namespace(
                target="example.com",
                ports="80",
                top_ports=None,
                port_profile=None,
                subfinder=False,
                amass=False,
                output=DEFAULT_TCP_TEXT_ARGUMENT,
                json_output=None,
                threads=None,
                timeout=None,
                max_rate=None,
                stance="balanced",
                quiet=True,
            )

            output = io.StringIO()
            with (
                patch("hylianscan.parse_arguments", return_value=args),
                patch("hylianscan.resolve_target", return_value=target),
                patch("hylianscan.resolve_output_workspace", return_value=workspace_dir),
                patch("hylianscan.run_port_scan", return_value=scan_result),
                redirect_stdout(output),
            ):
                hylianscan.main()

            rendered = output.getvalue()

            self.assertIsNone(ANSI_PATTERN.search(rendered))
            self.assertIn("No open ports found.", rendered)
            self.assertNotIn("Report saved to", rendered)
            self.assertTrue((workspace_dir / "tcp_report.txt").exists())

    def test_passive_discovery_quiet_disables_telemetry_callback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "subdomains.txt"

            with patch(
                "hylianscan.run_subfinder",
                return_value=["www.example.com"],
            ) as subfinder:
                summary = hylianscan.run_passive_subdomain_discovery(
                    domain="example.com",
                    providers=["subfinder"],
                    output_path=output_path,
                    quiet=True,
                )

            self.assertIn("Raw Discoveries: 1", summary)
            self.assertIn("Unique Subdomains: 1", summary)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "www.example.com\n")
            self.assertIsNone(subfinder.call_args.kwargs["telemetry_callback"])

    def test_passive_discovery_quiet_summary_is_plain_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "subdomains.txt"

            with patch(
                "hylianscan.run_subfinder",
                return_value=["www.example.com"],
            ):
                summary = hylianscan.run_passive_subdomain_discovery(
                    domain="example.com",
                    providers=["subfinder"],
                    output_path=output_path,
                    quiet=True,
                )

            self.assertIsNone(ANSI_PATTERN.search(summary))
            self.assertNotIn("SHEIKAH MAP UPDATED", summary)
            self.assertNotIn("=", summary)
            self.assertIn("Target: example.com", summary)
            self.assertIn("Raw Discoveries: 1", summary)
            self.assertIn("Unique Subdomains: 1", summary)
            self.assertIn(f"Output Path: {output_path.name}", summary)


if __name__ == "__main__":
    unittest.main()
