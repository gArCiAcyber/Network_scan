"""Tests for passive subdomain provider execution helpers."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import hylianscan
from modules.subdomain import (
    PassiveProviderResult,
    parse_plain_provider_line,
    parse_subfinder_json_line,
    resolve_provider_executable,
    run_amass,
    run_passive_provider,
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
            patch(
                "modules.subdomain.run_passive_provider",
                return_value=PassiveProviderResult(
                    provider="subfinder",
                    candidates=[],
                ),
            ) as provider,
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
            ["/opt/tools/subfinder", "-d", "example.com", "-silent", "-oJ", "-cs"],
        )

    def test_run_amass_builds_command_with_resolved_executable(self) -> None:
        with (
            patch(
                "modules.subdomain.resolve_provider_executable",
                return_value="/opt/tools/amass",
            ) as resolver,
            patch(
                "modules.subdomain.run_passive_provider",
                return_value=PassiveProviderResult(
                    provider="amass",
                    candidates=[],
                ),
            ) as provider,
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

    def test_subfinder_jsonl_parser_extracts_sources_from_fixture(self) -> None:
        fixture_path = Path(__file__).parent / "fixtures" / "subfinder_jsonl.txt"
        parsed = [
            parse_subfinder_json_line(line)
            for line in fixture_path.read_text(encoding="utf-8").splitlines()
        ]

        self.assertEqual(parsed[0].subdomain, "www.example.com")
        self.assertEqual(parsed[0].sources, ("crtsh",))
        self.assertEqual(parsed[1].subdomain, "api.example.com")
        self.assertEqual(parsed[1].sources, ("alienvault", "virustotal"))

    def test_subfinder_jsonl_parser_falls_back_to_plain_subdomain(self) -> None:
        parsed = parse_subfinder_json_line("www.example.com")

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.subdomain, "www.example.com")
        self.assertEqual(parsed.sources, ())

    def test_plain_provider_parser_does_not_claim_sources(self) -> None:
        parsed = parse_plain_provider_line("mail.example.com")

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.subdomain, "mail.example.com")
        self.assertEqual(parsed.sources, ())

    def test_run_subfinder_falls_back_when_json_source_mode_fails(self) -> None:
        failed_json_result = PassiveProviderResult(
            provider="subfinder",
            candidates=[],
            status="failed",
            exit_code=1,
            errors=["unknown flag: -cs"],
        )
        plain_result = PassiveProviderResult(
            provider="subfinder",
            candidates=["www.example.com"],
        )

        with (
            patch(
                "modules.subdomain.resolve_provider_executable",
                return_value="/opt/tools/subfinder",
            ),
            patch(
                "modules.subdomain.run_passive_provider",
                side_effect=[failed_json_result, plain_result],
            ) as provider,
        ):
            result = run_subfinder("example.com")

        self.assertEqual(result.candidates, ["www.example.com"])
        self.assertEqual(provider.call_count, 2)
        self.assertEqual(
            provider.call_args_list[0].kwargs["command"],
            ["/opt/tools/subfinder", "-d", "example.com", "-silent", "-oJ", "-cs"],
        )
        self.assertEqual(
            provider.call_args_list[1].kwargs["command"],
            ["/opt/tools/subfinder", "-d", "example.com", "-silent"],
        )
        self.assertIn(
            "Subfinder JSON source mode fallback: unknown flag: -cs",
            result.warnings,
        )

    def test_run_passive_provider_waits_without_timeout(self) -> None:
        process = MagicMock()
        process.stdout = ["www.example.com\n"]
        process.stderr = []
        process.wait.return_value = 0

        with patch("modules.subdomain.subprocess.Popen", return_value=process):
            result = run_passive_provider(
                domain="example.com",
                provider_name="Subfinder",
                command=["subfinder", "-d", "example.com", "-silent"],
            )

        process.wait.assert_called_once_with()
        self.assertFalse(result.timed_out)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.candidates, ["www.example.com"])

    def test_run_passive_provider_records_non_zero_exit_metadata(self) -> None:
        process = MagicMock()
        process.stdout = []
        process.stderr = ["error: provider failed\n"]
        process.wait.return_value = 2

        with patch("modules.subdomain.subprocess.Popen", return_value=process):
            result = run_passive_provider(
                domain="example.com",
                provider_name="Amass",
                command=["amass", "enum", "-passive", "-d", "example.com"],
            )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.exit_code, 2)
        self.assertFalse(result.timed_out)
        self.assertIn("Amass exited with status code 2.", result.errors)

    def test_run_passive_provider_terminates_process_on_keyboard_interrupt(self) -> None:
        process = MagicMock()
        process.stdout = []
        process.stderr = []
        process.wait.side_effect = [KeyboardInterrupt(), 0]

        with patch("modules.subdomain.subprocess.Popen", return_value=process):
            with self.assertRaises(KeyboardInterrupt):
                run_passive_provider(
                    domain="example.com",
                    provider_name="Amass",
                    command=["amass", "enum", "-passive", "-d", "example.com"],
                )

        process.terminate.assert_called_once_with()
        self.assertEqual(process.wait.call_args_list[0].args, ())
        self.assertEqual(process.wait.call_args_list[1].kwargs["timeout"], 5.0)

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

    def test_passive_discovery_saves_plain_txt_and_metadata_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "subdomains.txt"
            json_output_path = Path(temporary_dir) / "subdomains.json"

            with patch(
                "hylianscan.run_subfinder",
                return_value=PassiveProviderResult(
                    provider="subfinder",
                    candidates=["www.example.com", "api.example.com"],
                    observed_sources=["crtsh"],
                    candidate_sources={"www.example.com": ["crtsh"]},
                    status="completed",
                    exit_code=0,
                ),
            ):
                hylianscan.run_passive_subdomain_discovery(
                    domain="example.com",
                    providers=["subfinder"],
                    output_path=output_path,
                    json_output_path=json_output_path,
                    quiet=True,
                )

            self.assertEqual(
                output_path.read_text(encoding="utf-8"),
                "api.example.com\nwww.example.com\n",
            )

            document = json.loads(json_output_path.read_text(encoding="utf-8"))
            self.assertEqual(
                document["providers"][0]["metadata"]["observed_sources"],
                ["crtsh"],
            )
            self.assertEqual(
                document["providers"][0]["metadata"]["candidate_sources"],
                {"www.example.com": ["crtsh"]},
            )


if __name__ == "__main__":
    unittest.main()
