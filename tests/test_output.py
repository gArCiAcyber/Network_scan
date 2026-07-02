"""Tests for output path and persistence helpers."""

import tempfile
import unittest
from pathlib import Path

from core.output import (
    DEFAULT_TCP_JSON_ARGUMENT,
    DEFAULT_TCP_TEXT_ARGUMENT,
    OUTPUT_DIR,
    PROJECT_ROOT,
    resolve_nmap_import_json_output_path,
    resolve_nmap_import_output_path,
    resolve_output_workspace,
    resolve_json_output_path,
    resolve_output_path,
    resolve_subdomain_json_output_path,
    resolve_subdomain_output_path,
    sanitize_target_name,
    save_report,
    save_subdomain_results,
    should_create_passive_output_workspace,
    should_create_tcp_output_workspace,
)


class OutputHelperTests(unittest.TestCase):
    """Validate pure output helper behavior."""

    def test_sanitize_target_name_keeps_safe_domain_characters(self) -> None:
        self.assertEqual(sanitize_target_name("Example.COM"), "example.com")
        self.assertEqual(
            sanitize_target_name("https://example.com:443/path"),
            "https_example.com_443_path",
        )
        self.assertEqual(sanitize_target_name("   "), "target")

    def test_resolve_output_workspace_uses_target_and_timestamp(self) -> None:
        self.assertEqual(
            resolve_output_workspace("Example.COM", timestamp="20260616_120000"),
            OUTPUT_DIR / "example.com" / "20260616_120000",
        )

    def test_resolve_output_workspace_can_use_injected_timestamp_factory(self) -> None:
        self.assertEqual(
            resolve_output_workspace(
                "192.0.2.10",
                timestamp_factory=lambda: "20260616_121500",
            ),
            OUTPUT_DIR / "192.0.2.10" / "20260616_121500",
        )

    def test_resolve_output_path_handles_none_and_safe_filename(self) -> None:
        self.assertIsNone(resolve_output_path(None))
        self.assertEqual(
            resolve_output_path("reports/custom.txt"),
            OUTPUT_DIR / "custom.txt",
        )
        self.assertEqual(
            resolve_output_path(""),
            OUTPUT_DIR / "hylianscan_results.txt",
        )

    def test_resolve_output_path_uses_workspace_default_tcp_report_name(self) -> None:
        workspace_dir = OUTPUT_DIR / "example.com" / "20260616_120000"

        self.assertEqual(
            resolve_output_path(DEFAULT_TCP_TEXT_ARGUMENT, workspace_dir=workspace_dir),
            workspace_dir / "tcp_report.txt",
        )
        self.assertEqual(
            resolve_output_path("", workspace_dir=workspace_dir),
            workspace_dir / "tcp_report.txt",
        )

    def test_resolve_json_output_path_adds_json_suffix(self) -> None:
        self.assertIsNone(resolve_json_output_path(None))
        self.assertEqual(
            resolve_json_output_path("tcp_results"),
            OUTPUT_DIR / "tcp_results.json",
        )
        self.assertEqual(
            resolve_json_output_path("reports/tcp_results.json"),
            OUTPUT_DIR / "tcp_results.json",
        )
        self.assertEqual(
            resolve_json_output_path(""),
            OUTPUT_DIR / "hylianscan_tcp_results.json",
        )

    def test_resolve_json_output_path_uses_workspace_default_tcp_json_name(self) -> None:
        workspace_dir = OUTPUT_DIR / "example.com" / "20260616_120000"

        self.assertEqual(
            resolve_json_output_path(
                DEFAULT_TCP_JSON_ARGUMENT,
                workspace_dir=workspace_dir,
            ),
            workspace_dir / "tcp_results.json",
        )
        self.assertEqual(
            resolve_json_output_path("", workspace_dir=workspace_dir),
            workspace_dir / "tcp_results.json",
        )

    def test_resolve_subdomain_json_output_path_uses_subdomain_defaults(self) -> None:
        self.assertIsNone(resolve_subdomain_json_output_path(None))
        self.assertEqual(
            resolve_subdomain_json_output_path("subdomains"),
            OUTPUT_DIR / "subdomains.json",
        )
        self.assertEqual(
            resolve_subdomain_json_output_path("hylianscan_tcp_results.json"),
            OUTPUT_DIR / "hylianscan_subdomains.json",
        )
        self.assertEqual(
            resolve_subdomain_json_output_path(""),
            OUTPUT_DIR / "hylianscan_subdomains.json",
        )

    def test_resolve_subdomain_json_output_path_uses_workspace_default_name(self) -> None:
        workspace_dir = OUTPUT_DIR / "example.com" / "20260616_120000"

        self.assertEqual(
            resolve_subdomain_json_output_path(
                DEFAULT_TCP_JSON_ARGUMENT,
                workspace_dir=workspace_dir,
            ),
            workspace_dir / "subdomains.json",
        )
        self.assertEqual(
            resolve_subdomain_json_output_path("", workspace_dir=workspace_dir),
            workspace_dir / "subdomains.json",
        )

    def test_resolve_subdomain_output_path_handles_defaults_and_relative_dirs(self) -> None:
        self.assertEqual(
            resolve_subdomain_output_path(None),
            OUTPUT_DIR / "hylianscan_subdomains.txt",
        )
        self.assertEqual(
            resolve_subdomain_output_path("hylianscan_results.txt"),
            OUTPUT_DIR / "subdomains.txt",
        )
        self.assertEqual(
            resolve_subdomain_output_path("reports"),
            PROJECT_ROOT / "reports" / "subdomains.txt",
        )

    def test_resolve_subdomain_output_path_uses_workspace_default_name(self) -> None:
        workspace_dir = OUTPUT_DIR / "example.com" / "20260616_120000"

        self.assertEqual(
            resolve_subdomain_output_path(None, workspace_dir=workspace_dir),
            workspace_dir / "subdomains.txt",
        )
        self.assertEqual(
            resolve_subdomain_output_path(
                DEFAULT_TCP_TEXT_ARGUMENT,
                workspace_dir=workspace_dir,
            ),
            workspace_dir / "subdomains.txt",
        )

    def test_resolve_subdomain_output_path_preserves_absolute_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            expected_path = Path(temporary_dir) / "subdomains.txt"

            self.assertEqual(
                resolve_subdomain_output_path(temporary_dir),
                expected_path,
            )

    def test_resolve_nmap_import_output_path_uses_import_defaults(self) -> None:
        self.assertIsNone(resolve_nmap_import_output_path(None))
        self.assertEqual(
            resolve_nmap_import_output_path(DEFAULT_TCP_TEXT_ARGUMENT),
            OUTPUT_DIR / "nmap_import_report.txt",
        )
        self.assertEqual(
            resolve_nmap_import_output_path("custom.txt"),
            OUTPUT_DIR / "custom.txt",
        )

    def test_resolve_nmap_import_json_output_path_uses_import_defaults(self) -> None:
        self.assertIsNone(resolve_nmap_import_json_output_path(None))
        self.assertEqual(
            resolve_nmap_import_json_output_path(DEFAULT_TCP_JSON_ARGUMENT),
            OUTPUT_DIR / "nmap_import_results.json",
        )
        self.assertEqual(
            resolve_nmap_import_json_output_path("nmap-import"),
            OUTPUT_DIR / "nmap-import.json",
        )

    def test_workspace_creation_detection_for_tcp_defaults(self) -> None:
        self.assertFalse(should_create_tcp_output_workspace(None, None))
        self.assertTrue(should_create_tcp_output_workspace(DEFAULT_TCP_TEXT_ARGUMENT, None))
        self.assertTrue(should_create_tcp_output_workspace(None, DEFAULT_TCP_JSON_ARGUMENT))
        self.assertFalse(should_create_tcp_output_workspace("custom.txt", "custom.json"))

    def test_workspace_creation_detection_for_passive_defaults(self) -> None:
        self.assertTrue(should_create_passive_output_workspace(None, None))
        self.assertTrue(
            should_create_passive_output_workspace(DEFAULT_TCP_TEXT_ARGUMENT, None)
        )
        self.assertTrue(
            should_create_passive_output_workspace(None, DEFAULT_TCP_JSON_ARGUMENT)
        )
        self.assertFalse(should_create_passive_output_workspace("reports", "custom.json"))

    def test_save_report_writes_text_with_trailing_newline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "nested" / "report.txt"

            save_report("report body", output_path)

            self.assertEqual(output_path.read_text(encoding="utf-8"), "report body\n")

    def test_save_report_strips_ansi_from_normal_report_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "report.txt"

            save_report("\x1b[1;32mcolored report\x1b[0m", output_path)

            saved_report = output_path.read_text(encoding="utf-8")
            self.assertEqual(saved_report, "colored report\n")
            self.assertNotIn("\x1b[", saved_report)

    def test_save_report_keeps_quiet_text_plain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "quiet-report.txt"

            save_report("Target: example.com\nNo open ports found.", output_path)

            saved_report = output_path.read_text(encoding="utf-8")
            self.assertEqual(
                saved_report,
                "Target: example.com\nNo open ports found.\n",
            )
            self.assertNotIn("\x1b[", saved_report)

    def test_save_report_ignores_none_output_path(self) -> None:
        self.assertIsNone(save_report("report body", None))

    def test_save_subdomain_results_writes_one_subdomain_per_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "nested" / "subdomains.txt"

            save_subdomain_results(["a.example.com", "b.example.com"], output_path)

            self.assertEqual(
                output_path.read_text(encoding="utf-8"),
                "a.example.com\nb.example.com\n",
            )


if __name__ == "__main__":
    unittest.main()
