"""Tests for passive subdomain provider execution helpers."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import hylianscan
from modules.subdomain import (
    resolve_provider_executable,
    run_amass,
    run_subfinder,
)


class PassiveProviderExecutableTests(unittest.TestCase):
    """Validate provider executable resolution without running external tools."""

    def test_provider_command_resolution_uses_default_command_from_path(self) -> None:
        with patch("modules.subdomain.shutil.which", return_value="/usr/bin/subfinder"):
            executable = resolve_provider_executable(
                provider_name="Subfinder",
                default_command="subfinder",
                path_option="--subfinder-path",
            )

        self.assertEqual(executable, "subfinder")

    def test_provider_command_resolution_uses_explicit_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            executable_path = Path(temporary_dir) / "subfinder"
            executable_path.write_text("#!/bin/sh\n", encoding="utf-8")

            with patch("modules.subdomain.os.access", return_value=True):
                executable = resolve_provider_executable(
                    provider_name="Subfinder",
                    default_command="subfinder",
                    path_option="--subfinder-path",
                    explicit_path=str(executable_path),
                )

        self.assertEqual(executable, str(executable_path))

    def test_provider_command_resolution_reports_missing_default_provider(self) -> None:
        with patch("modules.subdomain.shutil.which", return_value=None):
            with self.assertRaisesRegex(
                ValueError,
                "Subfinder executable was not found.*PATH.*--subfinder-path",
            ):
                resolve_provider_executable(
                    provider_name="Subfinder",
                    default_command="subfinder",
                    path_option="--subfinder-path",
                )

    def test_provider_command_resolution_reports_missing_explicit_path(self) -> None:
        missing_path = str(Path("missing") / "subfinder")

        with self.assertRaisesRegex(
            ValueError,
            "Subfinder executable path does not exist.*--subfinder-path",
        ):
            resolve_provider_executable(
                provider_name="Subfinder",
                default_command="subfinder",
                path_option="--subfinder-path",
                explicit_path=missing_path,
            )

    def test_provider_command_resolution_reports_non_executable_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            with self.assertRaisesRegex(
                ValueError,
                "Amass executable path is not executable.*--amass-path",
            ):
                resolve_provider_executable(
                    provider_name="Amass",
                    default_command="amass",
                    path_option="--amass-path",
                    explicit_path=temporary_dir,
                )

    def test_run_subfinder_builds_command_with_resolved_executable(self) -> None:
        with (
            patch(
                "modules.subdomain.resolve_provider_executable",
                return_value="/opt/tools/subfinder",
            ) as resolver,
            patch("modules.subdomain.run_passive_provider", return_value=[]) as provider,
        ):
            run_subfinder("example.com", executable_path="/opt/tools/subfinder")

        resolver.assert_called_once_with(
            provider_name="Subfinder",
            default_command="subfinder",
            path_option="--subfinder-path",
            explicit_path="/opt/tools/subfinder",
        )
        self.assertEqual(
            provider.call_args.kwargs["command"],
            ["/opt/tools/subfinder", "-d", "example.com", "-silent"],
        )

    def test_run_amass_builds_command_with_resolved_executable(self) -> None:
        with (
            patch(
                "modules.subdomain.resolve_provider_executable",
                return_value="/opt/tools/amass",
            ) as resolver,
            patch("modules.subdomain.run_passive_provider", return_value=[]) as provider,
        ):
            run_amass("example.com", executable_path="/opt/tools/amass")

        resolver.assert_called_once_with(
            provider_name="Amass",
            default_command="amass",
            path_option="--amass-path",
            explicit_path="/opt/tools/amass",
        )
        self.assertEqual(
            provider.call_args.kwargs["command"],
            ["/opt/tools/amass", "enum", "-passive", "-d", "example.com"],
        )

    def test_passive_discovery_forwards_provider_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "subdomains.txt"

            with (
                patch("hylianscan.run_subfinder", return_value=["www.example.com"]) as subfinder,
                patch("hylianscan.run_amass", return_value=["api.example.com"]) as amass,
            ):
                summary = hylianscan.run_passive_subdomain_discovery(
                    domain="example.com",
                    providers=["subfinder", "amass"],
                    output_path=output_path,
                    provider_paths={
                        "subfinder": "/opt/tools/subfinder",
                        "amass": "/opt/tools/amass",
                    },
                    quiet=True,
                )

        self.assertIn("Raw Discoveries: 2", summary)
        self.assertIn("Unique Subdomains: 2", summary)
        self.assertEqual(
            subfinder.call_args.kwargs["executable_path"],
            "/opt/tools/subfinder",
        )
        self.assertEqual(amass.call_args.kwargs["executable_path"], "/opt/tools/amass")


if __name__ == "__main__":
    unittest.main()
