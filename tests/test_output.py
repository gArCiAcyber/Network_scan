"""Tests for output path and persistence helpers."""

import tempfile
import unittest
from pathlib import Path

from core.output import (
    OUTPUT_DIR,
    PROJECT_ROOT,
    resolve_json_output_path,
    resolve_output_path,
    resolve_subdomain_json_output_path,
    resolve_subdomain_output_path,
    save_report,
    save_subdomain_results,
)


class OutputHelperTests(unittest.TestCase):
    """Validate pure output helper behavior."""

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

    def test_resolve_subdomain_output_path_preserves_absolute_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            expected_path = Path(temporary_dir) / "subdomains.txt"

            self.assertEqual(
                resolve_subdomain_output_path(temporary_dir),
                expected_path,
            )

    def test_save_report_writes_text_with_trailing_newline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "nested" / "report.txt"

            save_report("report body", output_path)

            self.assertEqual(output_path.read_text(encoding="utf-8"), "report body\n")

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
