"""Offline regression checks for provider policy, startup, and release monitoring."""

from contextlib import redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import hylianscan
from modules.provider_compatibility import PROVIDERS, classify_version, missing_flags
from modules.subdomain import ProviderRunResult, inspect_provider_compatibility
from scripts.check_provider import LimitedEvidence, check_subfinder
from scripts.summarize_provider_checks import propose_promotions, summarize
from scripts.provider_updates import collect_updates, install_release, stable_version


class CompatibilityTests(unittest.TestCase):
    def test_policy_keeps_new_versions_unverified_and_rejects_unknown_majors(self):
        self.assertEqual(classify_version("subfinder", "2.13.0"), "tested")
        for tool, spec in PROVIDERS.items():
            with self.subTest(tool=tool):
                self.assertEqual(classify_version(tool, spec["baseline"]), "tested")
                major = spec["supported_majors"][-1]
                self.assertEqual(classify_version(tool, f"{major}.999.0"), "untested")
                self.assertEqual(classify_version(tool, "99.0.0"), "unsupported")
                self.assertEqual(classify_version(tool, spec["baseline"] + "-rc.1"), "unsupported")
        self.assertEqual(classify_version("amass", "5.1.1"), "unsupported")
        self.assertIn("-a", missing_flags("dnsx", "-aaaa -silent"))

    def test_real_runner_reads_version_and_help_from_both_streams(self):
        popen = subprocess.Popen
        for stream in ("stdout", "stderr"):
            for tool, spec in PROVIDERS.items():
                with self.subTest(tool=tool, stream=stream):
                    def launch(command, **kwargs):
                        output = (f"Version: v{spec['baseline']}" if "-version" in command
                                  else "\n".join(spec["required_flags"]) + "\n" + "help text\n" * 50)
                        return popen([sys.executable, "-c", f"import sys; print({output!r}, file=sys.{stream})"], **kwargs)
                    with patch("modules.subdomain.subprocess.Popen", side_effect=launch):
                        result = inspect_provider_compatibility(tool, "fixture", timeout=3)
                    self.assertEqual(result["version"], spec["baseline"])
                    self.assertEqual(result["status"], "tested")

    def test_bad_versions_warn_but_missing_flags_fail_closed(self):
        for output, help_output, status, expected in (
            ("unknown", "-d -passive", "unverified", "missing or ambiguous"),
            ("4.2.0 3.23.3", "-d -passive", "unverified", "missing or ambiguous"),
            ("5.1.1", "-d -passive", "unsupported", "engine/session"),
        ):
            with self.subTest(output=output, help=help_output):
                def run(*args, **kwargs):
                    kwargs["output_parser"](output if "-version" in args[2] else help_output)
                    return ProviderRunResult([], "completed", 0)
                with patch("modules.subdomain.run_passive_provider", side_effect=run):
                    result = inspect_provider_compatibility("amass", "amass")
                self.assertEqual(result["status"], status)
                self.assertIn(expected, result["reason"])
        with patch("modules.subdomain.run_passive_provider", side_effect=lambda *args, **kwargs: (
            kwargs["output_parser"]("4.2.0" if "-version" in args[2] else "-domain -passive")
            or ProviderRunResult([], "completed", 0)
        )), self.assertRaisesRegex(ValueError, "missing required options: -d"):
            inspect_provider_compatibility("amass", "amass")

    def test_version_process_timeout_and_nonzero_exit_fail_and_are_reaped(self):
        popen = subprocess.Popen
        for script in ("import time; time.sleep(30)", "print('4.2.0'); raise SystemExit(7)"):
            processes = []
            def launch(command, **kwargs):
                process = popen([sys.executable, "-c", script], **kwargs)
                processes.append(process)
                return process
            with self.subTest(script=script), \
                    patch("modules.subdomain.subprocess.Popen", side_effect=launch), \
                    redirect_stderr(io.StringIO()), self.assertRaises(ValueError):
                inspect_provider_compatibility("amass", "fixture", timeout=0.15)
            self.assertTrue(all(process.poll() is not None for process in processes))

    def test_unsupported_provider_warns_and_discovery_continues(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "subdomains.txt"
            warning = io.StringIO()
            with (
                patch("hylianscan.resolve_provider_executable", side_effect=lambda **kw: kw["default_command"]),
                patch("hylianscan.inspect_provider_compatibility", side_effect=[
                    {"status": "tested", "version": "2.16.0"},
                    {"status": "unsupported", "version": "5.1.1", "reason": "Amass 5 needs integration."},
                ]),
                patch("hylianscan.run_subfinder", return_value=ProviderRunResult(
                    ["www.example.test"], "completed", 0,
                )) as subfinder,
                patch("hylianscan.run_amass", return_value=ProviderRunResult(
                    [], "completed", 0,
                )) as amass,
                redirect_stderr(warning),
            ):
                hylianscan.run_passive_subdomain_discovery(
                    "example.test", ["subfinder", "amass"], output, quiet=True,
                )
            subfinder.assert_called_once()
            amass.assert_called_once()
            self.assertEqual(output.read_text(), "www.example.test\n")
            self.assertIn("unsupported", warning.getvalue())

    def test_untested_warning_budget_and_json_evidence(self):
        checked = {"status": "untested", "version": "2.999.0", "executable": "subfinder"}
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("hylianscan.resolve_provider_executable", return_value="subfinder"),
            patch("hylianscan.inspect_provider_compatibility", return_value=checked) as inspect,
            patch("hylianscan.time.monotonic", side_effect=[10, 10.25]),
            patch("hylianscan.run_subfinder", return_value=ProviderRunResult([], "completed", 0)) as run,
            redirect_stderr(io.StringIO()) as warning,
        ):
            report = Path(directory) / "report.json"
            hylianscan.run_passive_subdomain_discovery(
                "example.test", ["subfinder"], Path(directory) / "subdomains.txt", report,
                quiet=True, provider_timeouts={"subfinder": 1},
            )
            self.assertEqual(json.loads(report.read_text())["providers"][0]["compatibility"], checked)
        inspect.assert_called_once_with("subfinder", "subfinder", timeout=1)
        self.assertEqual(run.call_args.kwargs["timeout"], 0.75)
        self.assertIn("untested", warning.getvalue())


class ReleaseMonitorTests(unittest.TestCase):
    def test_subfinder_smoke_uses_reserved_target_and_preserves_evidence(self):
        completed = ProviderRunResult(["api.example.test"], "completed", 0, elapsed_seconds=0.1)
        empty = ProviderRunResult([], "completed", 0, elapsed_seconds=0.1)
        rejected = ProviderRunResult([], "failed", 2, diagnostics=("unknown option",))
        with patch("scripts.check_provider.run_passive_provider", side_effect=[completed, empty, rejected]) as run:
            evidence = check_subfinder(Path("subfinder"))
        self.assertEqual(evidence["normal_output"]["subdomains"], ["api.example.test"])
        self.assertEqual(evidence["empty_output"]["subdomains"], [])
        self.assertEqual(evidence["unknown_option"]["exit_code"], 2)
        self.assertIn("example.test", run.call_args_list[0].args[2])
        with patch("scripts.check_provider.run_passive_provider", return_value=empty), \
                self.assertRaises(LimitedEvidence):
            check_subfinder(Path("subfinder"))

    def test_monitor_checks_baseline_latest_and_requested_history(self):
        releases = {"subfinder": "v2.999.0", "amass": "v5.1.1", "dnsx": "v1.3.1"}
        before = json.dumps(PROVIDERS, sort_keys=True)
        with patch("scripts.provider_updates.github_json", side_effect=lambda repo, endpoint:
                   {"tag_name": releases[repo.split('/')[-1]], "draft": False, "prerelease": False}):
            updates, matrix = collect_updates("subfinder", "2.13.0")
        self.assertEqual(updates["subfinder"]["status"], "untested")
        self.assertEqual(updates["amass"]["status"], "unsupported")
        self.assertIn({"provider": "subfinder", "version": "2.999.0"}, matrix)
        self.assertIn({"provider": "amass", "version": "5.1.1"}, matrix)
        self.assertIn({"provider": "subfinder", "version": "2.13.0"}, matrix)
        self.assertEqual(updates["subfinder"]["requested"], "2.13.0")
        for tool, spec in PROVIDERS.items():
            self.assertIn({"provider": tool, "version": spec["baseline"]}, matrix)
        self.assertEqual(json.dumps(PROVIDERS, sort_keys=True), before)

    def test_report_requires_both_platforms_before_proposing_promotion(self):
        manifest = {"matrix": [{"provider": "subfinder", "version": "2.17.0"}]}
        evidence = [
            {"provider": "subfinder", "expected_version": "2.17.0", "platform": platform,
             "architecture": "AMD64" if platform == "Windows" else "x86_64",
             "status": "passed", "classification": "approved"}
            for platform in ("Linux", "Windows")
        ]
        report = summarize(manifest, evidence, "success")
        registry = json.loads(json.dumps(PROVIDERS))
        self.assertEqual(report["results"][0]["classification"], "approved")
        self.assertEqual(
            propose_promotions(report, registry),
            [{"provider": "subfinder", "version": "2.17.0"}],
        )
        limited = summarize(manifest, evidence[:1], "success")
        self.assertEqual(limited["results"][0]["classification"], "limited")
        self.assertEqual(propose_promotions(limited, json.loads(json.dumps(PROVIDERS))), [])
        evidence[0].update(status="failed", classification="incompatible")
        incompatible = summarize(manifest, evidence, "success")
        self.assertEqual(incompatible["results"][0]["classification"], "incompatible")
        unsupported = {"results": [{
            "provider": "amass", "version": "5.1.1", "classification": "approved",
        }]}
        self.assertEqual(propose_promotions(unsupported, json.loads(json.dumps(PROVIDERS))), [])

    def test_release_api_failure_preserves_existing_manifest(self):
        from scripts.provider_updates import main
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "updates.json"
            output.write_text("existing manifest")
            with patch("sys.argv", ["updates", "monitor", "--output", str(output)]), \
                    patch("scripts.provider_updates.github_json", side_effect=OSError("API unavailable")), \
                    self.assertRaises(OSError):
                main()
            self.assertEqual(output.read_text(), "existing manifest")

    def test_release_tags_cannot_be_prereleases_or_commands(self):
        self.assertEqual(stable_version("v2.16.0"), "2.16.0")
        for tag in ("v2.0.0-rc.1", "latest", "v1.0.0;command", "1.0.0\ncommand"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                stable_version(tag)

    def test_installer_checks_digest_and_extracts_only_the_named_executable(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("../../subfinder.exe", b"fixture executable")
            bundle.writestr("../../unwanted.txt", b"must not be extracted")
        data = archive.getvalue()
        asset = {
            "name": "subfinder_2.16.0_windows_amd64.zip",
            "browser_download_url": "https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder.zip",
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        }
        for valid_digest in (True, False):
            with self.subTest(valid_digest=valid_digest), tempfile.TemporaryDirectory() as directory:
                if not valid_digest:
                    asset["digest"] = "sha256:" + "0" * 64
                with (
                    patch("scripts.provider_updates.platform.system", return_value="Windows"),
                    patch("scripts.provider_updates.platform.machine", return_value="AMD64"),
                    patch("scripts.provider_updates.github_json", return_value={"assets": [asset]}),
                    patch("scripts.provider_updates.urlopen", return_value=io.BytesIO(data)),
                ):
                    if valid_digest:
                        binary = install_release("subfinder", "2.16.0", Path(directory))
                        self.assertEqual(binary, Path(directory) / "subfinder.exe")
                        self.assertEqual(binary.read_bytes(), b"fixture executable")
                        self.assertEqual(list(Path(directory).iterdir()), [binary])
                    else:
                        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                            install_release("subfinder", "2.16.0", Path(directory))
                        self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
