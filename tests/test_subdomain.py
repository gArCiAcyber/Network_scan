"""Tests for passive subdomain provider execution helpers."""

import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import hylianscan
from modules.subdomain import (
    ProviderRunResult,
    ProviderInterrupted,
    resolve_provider_executable,
    run_amass,
    run_dnsx,
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
                return_value=ProviderRunResult([], "completed", 0),
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
            ["/opt/tools/subfinder", "-d", "example.com", "-silent"],
        )

    def test_run_amass_builds_command_with_resolved_executable(self) -> None:
        with (
            patch(
                "modules.subdomain.resolve_provider_executable",
                return_value="/opt/tools/amass",
            ) as resolver,
            patch(
                "modules.subdomain.run_passive_provider",
                side_effect=[ProviderRunResult([], "completed", 0, diagnostics=("v4.2.0",)),
                             ProviderRunResult([], "completed", 0)],
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

    def test_run_dnsx_resolves_candidates_from_stdin(self) -> None:
        with (
            patch(
                "modules.subdomain.resolve_provider_executable",
                return_value="/opt/tools/dnsx",
            ) as resolver,
            patch(
                "modules.subdomain.run_passive_provider",
                return_value=ProviderRunResult([], "completed", 0),
            ) as provider,
        ):
            run_dnsx(
                ["api.example.com", "www.example.com"],
                executable_path="/opt/tools/dnsx",
            )

        resolver.assert_called_once_with(
            provider_name="DNSx",
            default_command="dnsx",
            path_option="--dnsx-path",
            explicit_path="/opt/tools/dnsx",
        )
        self.assertEqual(
            provider.call_args.kwargs["command"],
            ["/opt/tools/dnsx", "-silent", "-no-color", "-a", "-aaaa"],
        )
        self.assertEqual(
            provider.call_args.kwargs["input_text"],
            "api.example.com\nwww.example.com\n",
        )

    def test_run_dnsx_builds_address_family_and_operational_flags(self) -> None:
        expected_records = {
            "ipv4": ["-a"],
            "ipv6": ["-aaaa"],
            "dual-stack": ["-a", "-aaaa"],
        }

        for family, record_flags in expected_records.items():
            with (
                self.subTest(family=family),
                patch(
                    "modules.subdomain.resolve_provider_executable",
                    return_value="dnsx",
                ),
                patch(
                    "modules.subdomain.run_passive_provider",
                    return_value=ProviderRunResult([], "completed", 0),
                ) as provider,
            ):
                run_dnsx(
                    ["api.example.com"],
                    address_family=family,
                    resolver="1.1.1.1,8.8.8.8",
                    threads=25,
                    rate_limit=100,
                    query_timeout=2.5,
                    retry=3,
                    auto_wildcard=True,
                )

            self.assertEqual(
                provider.call_args.kwargs["command"],
                [
                    "dnsx",
                    "-silent",
                    "-no-color",
                    *record_flags,
                    "-r",
                    "1.1.1.1,8.8.8.8",
                    "-t",
                    "25",
                    "-rl",
                    "100",
                    "-timeout",
                    "2.5s",
                    "-retry",
                    "3",
                    "-auto-wildcard",
                ],
            )

    def test_run_dnsx_validates_explicit_path_without_candidates(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "DNSx executable path does not exist.*--dnsx-path",
        ):
            run_dnsx([], executable_path="missing-dnsx")

    def test_run_dnsx_skips_without_resolving_default_path_without_candidates(self) -> None:
        with patch("modules.subdomain.resolve_provider_executable") as resolver:
            result = run_dnsx([])

        self.assertEqual(result, ProviderRunResult([], "skipped", reason="No candidate subdomains to resolve."))
        resolver.assert_not_called()

    def test_run_dnsx_parses_opt_in_jsonl_metadata(self) -> None:
        def run_provider(**kwargs: object) -> ProviderRunResult:
            output_parser = kwargs["output_parser"]
            self.assertIsNotNone(output_parser)
            self.assertEqual(
                output_parser('{"host":"API.EXAMPLE.COM","a":["192.0.2.1"]}'),
                "API.EXAMPLE.COM",
            )
            return ProviderRunResult(["api.example.com"], "completed", 0)

        with (
            patch(
                "modules.subdomain.resolve_provider_executable",
                return_value="dnsx",
            ),
            patch(
                "modules.subdomain.run_passive_provider",
                side_effect=run_provider,
            ) as provider,
        ):
            result = run_dnsx(["api.example.com"], json_output=True)

        self.assertIn("-j", provider.call_args.kwargs["command"])
        self.assertEqual(
            result.metadata,
            [{"host": "API.EXAMPLE.COM", "a": ["192.0.2.1"]}],
        )

    def test_cli_forwards_dnsx_controls_to_passive_orchestration(self) -> None:
        args = argparse.Namespace(
            target="example.com",
            output=None,
            json_output="report.json",
            quiet=True,
            subfinder=True,
            amass=False,
            dnsx=True,
            address_family="ipv6",
            dnsx_resolver="1.1.1.1",
            dnsx_threads=25,
            dnsx_rate_limit=100,
            dnsx_timeout=2.5,
            dnsx_retry=3,
            dnsx_auto_wildcard=True,
            dnsx_json=True,
        )

        with (
            patch("hylianscan.parse_arguments", return_value=args),
            patch("hylianscan.run_passive_subdomain_discovery", return_value="done") as run,
            redirect_stdout(io.StringIO()),
        ):
            hylianscan.main()

        self.assertEqual(run.call_args.kwargs["address_family"], "ipv6")
        self.assertEqual(run.call_args.kwargs["dnsx_resolver"], "1.1.1.1")
        self.assertEqual(run.call_args.kwargs["dnsx_threads"], 25)
        self.assertEqual(run.call_args.kwargs["dnsx_rate_limit"], 100)
        self.assertEqual(run.call_args.kwargs["dnsx_timeout"], 2.5)
        self.assertEqual(run.call_args.kwargs["dnsx_retry"], 3)
        self.assertTrue(run.call_args.kwargs["dnsx_auto_wildcard"])
        self.assertTrue(run.call_args.kwargs["dnsx_json"])

    def test_passive_discovery_forwards_provider_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "subdomains.txt"

            with (
                patch(
                    "hylianscan.run_subfinder",
                    return_value=ProviderRunResult(
                        ["www.example.com"], "completed", 0
                    ),
                ) as subfinder,
                patch(
                    "hylianscan.run_amass",
                    return_value=ProviderRunResult(
                        ["api.example.com"], "completed", 0
                    ),
                ) as amass,
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

    def test_cli_writes_partial_reports_before_provider_failure_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "subdomains.txt"
            json_output_path = Path(temporary_dir) / "subdomains.json"
            args = argparse.Namespace(
                target="example.com",
                output="reports",
                json_output="report.json",
                quiet=True,
                subfinder=True,
                amass=False,
                dnsx=False,
            )
            failed_result = ProviderRunResult(
                ["api.example.com"],
                "failed",
                7,
                "Exited with status code 7.",
            )
            terminal_output = io.StringIO()

            with (
                patch("hylianscan.parse_arguments", return_value=args),
                patch(
                    "hylianscan.resolve_subdomain_output_path",
                    return_value=output_path,
                ),
                patch(
                    "hylianscan.resolve_subdomain_json_output_path",
                    return_value=json_output_path,
                ),
                patch("hylianscan.run_subfinder", return_value=failed_result),
                redirect_stdout(terminal_output),
                self.assertRaises(SystemExit) as exit_context,
            ):
                hylianscan.main()

            document = json.loads(json_output_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_context.exception.code, 1)
            self.assertIn(
                "Error: Passive discovery completed with provider errors",
                terminal_output.getvalue(),
            )
            self.assertIn("Partial results were saved", terminal_output.getvalue())
            self.assertEqual(
                output_path.read_text(encoding="utf-8"),
                "api.example.com\n",
            )
            self.assertEqual(document["results"]["subdomains"], ["api.example.com"])
            self.assertEqual(document["providers"][0]["status"], "failed")
            self.assertEqual(document["providers"][0]["exit_code"], 7)

    def test_nonzero_provider_exit_warns_and_keeps_partial_results(self) -> None:
        errors = io.StringIO()
        command = [
            sys.executable,
            "-c",
            "print('api.example.com'); raise SystemExit(7)",
        ]

        with redirect_stderr(errors):
            results = run_passive_provider("example.com", "Fake", command)

        self.assertEqual(results.subdomains, ["api.example.com"])
        self.assertEqual(results.status, "failed")
        self.assertEqual(results.exit_code, 7)
        self.assertEqual(results.reason, "Exited with status code 7.")
        self.assertIn("exited with status code 7", errors.getvalue())
        self.assertIn("partial results", errors.getvalue())

    def test_provider_timeout_keeps_partial_results_and_status(self) -> None:
        errors = io.StringIO()
        command = [
            sys.executable,
            "-u",
            "-c",
            "import time; print('api.example.com', flush=True); time.sleep(10)",
        ]

        with redirect_stderr(errors):
            result = run_passive_provider(
                "example.com",
                "Fake",
                command,
                timeout=0.5,
            )

        self.assertEqual(result.subdomains, ["api.example.com"])
        self.assertEqual(result.status, "timed_out")
        self.assertIsNone(result.exit_code)
        self.assertEqual(result.reason, "Timed out after 0.5 seconds.")
        self.assertIn("timed out", errors.getvalue())

    def test_passive_provider_can_consume_stdin(self) -> None:
        command = [
            sys.executable,
            "-c",
            "import sys; print(sys.stdin.read().splitlines()[0])",
        ]

        results = run_passive_provider(
            "example.com",
            "DNSx",
            command,
            input_text="api.example.com\n",
        )

        self.assertEqual(results.subdomains, ["api.example.com"])
        self.assertEqual(results.status, "completed")
        self.assertEqual(results.exit_code, 0)

    def test_large_unread_stdin_obeys_deadline(self) -> None:
        started = time.monotonic()
        with redirect_stderr(io.StringIO()):
            result = run_passive_provider(
                "example.com", "Fake",
                [sys.executable, "-u", "-c",
                 "import time; print('api.example.com'); time.sleep(5)"],
                timeout=0.3, input_text="api.example.com\n" * 100000,
            )
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(result.status, "timed_out")
        self.assertEqual(result.subdomains, ["api.example.com"])

    @unittest.skipUnless(os.name == "posix", "POSIX process-group signals")
    def test_sigterm_output_is_preserved_before_forced_shutdown(self) -> None:
        script = (
            "import signal,time; "
            "signal.signal(signal.SIGTERM, lambda *_: print('last.example.com', flush=True)); "
            "print('api.example.com', flush=True); time.sleep(5)"
        )
        with (patch("modules.subdomain.PROVIDER_SHUTDOWN_GRACE_SECONDS", 0.1),
              redirect_stderr(io.StringIO())):
            started = time.monotonic()
            result = run_passive_provider("example.com", "Fake",
                                          [sys.executable, "-u", "-c", script], timeout=0.5)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(result.status, "timed_out")
        self.assertEqual(result.subdomains, ["api.example.com", "last.example.com"])

    def test_descendant_output_handles_do_not_delay_parent_completion(self) -> None:
        # Descendant has a finite lifetime even when run against the old broken code.
        command = [sys.executable, "-u", "-c",
                   "import subprocess,sys; "
                   "subprocess.Popen([sys.executable,'-c','import time; time.sleep(4)'], "
                   "stdout=sys.stdout,stderr=sys.stderr); print('api.example.com')"]
        started = time.monotonic()
        result = run_passive_provider("example.com", "Fake", command, timeout=0.5)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(result.subdomains, ["api.example.com"])
        self.assertEqual(result.status, "completed")

    def test_interrupt_reaps_child_and_carries_partial_evidence(self) -> None:
        def interrupt_after_result(message: str) -> None:
            if "first result observed" in message:
                raise KeyboardInterrupt

        launched = []
        popen = subprocess.Popen

        def launch(*args, **kwargs):
            process = popen(*args, **kwargs)
            launched.append(process)
            return process

        with patch("modules.subdomain.subprocess.Popen", side_effect=launch):
            with self.assertRaises(ProviderInterrupted) as context:
                run_passive_provider(
                    "example.com", "Fake", [sys.executable, "-u", "-c",
                    "import time; print('api.example.com'); time.sleep(5)"],
                    telemetry_callback=interrupt_after_result,
                )
        self.assertEqual(context.exception.result.status, "interrupted")
        self.assertEqual(context.exception.result.subdomains, ["api.example.com"])
        self.assertTrue(all(process.poll() is not None for process in launched))

    def test_output_fragments_stderr_volume_and_scope(self) -> None:
        script = (
            "import sys,time; sys.stdout.write('api.exa'); sys.stdout.flush(); "
            "time.sleep(.1); sys.stdout.write('mple.com\\n'); "
            "sys.stderr.write('upstream timeout\\n'*10000); "
            "print('example.com.evil.test'); print('badexample.com'); "
            "print('192.0.2.1'); print('https://api.example.com'); "
            "print('api.example.com', end='')"
        )
        result = run_passive_provider("example.com", "Fake", [sys.executable, "-u", "-c", script])
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.subdomains, ["api.example.com"])
        self.assertEqual(len(result.diagnostics), 20)
        self.assertIn("upstream timeout", result.diagnostics)

    def test_amass_v3_hostname_output(self) -> None:
        popen = subprocess.Popen

        def launch(command, **kwargs):
            script = "print('v3.23.3')" if "-version" in command else "print('api.example.com')"
            return popen([sys.executable, "-u", "-c", script], **kwargs)

        with (patch("modules.subdomain.shutil.which", return_value="amass"),
              patch("modules.subdomain.subprocess.Popen", side_effect=launch)):
            result = run_amass("example.com")
        self.assertEqual(result.subdomains, ["api.example.com"])
        self.assertEqual(result.status, "completed")

    def test_dnsx_rejects_unrequested_output_and_preserves_interrupt_metadata(self) -> None:
        def interrupt(**kwargs):
            parser = kwargs["output_parser"]
            self.assertIsNone(parser('{"host":"other.test"}'))
            self.assertEqual(parser('{"host":"api.example.com"}'), "api.example.com")
            raise ProviderInterrupted(ProviderRunResult(["api.example.com"], "interrupted"))

        with (patch("modules.subdomain.shutil.which", return_value="dnsx"),
              patch("modules.subdomain.run_passive_provider", side_effect=interrupt),
              self.assertRaises(ProviderInterrupted) as context):
            run_dnsx(["api.example.com"], json_output=True)
        self.assertEqual(context.exception.result.metadata, [{"host": "api.example.com"}])

    def test_cli_interrupt_saves_provider_evidence_and_exits_130(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(target="example.com", output=None, json_output=None,
                                      quiet=True, subfinder=True, amass=False, dnsx=False)
            output = Path(directory) / "subdomains.txt"
            partial = ProviderRunResult(["api.example.com"], "interrupted", diagnostics=("source timeout",))
            with (patch("hylianscan.parse_arguments", return_value=args),
                  patch("hylianscan.resolve_subdomain_output_path", return_value=output),
                  patch("hylianscan.run_subfinder", side_effect=ProviderInterrupted(partial)),
                  redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as context):
                hylianscan.main()
            self.assertEqual(context.exception.code, 130)
            self.assertEqual(output.read_text().splitlines(), ["api.example.com"])
            self.assertIn("source timeout", (Path(directory)/"subdomains_providers.log").read_text())

    def test_amass_v5_rejected_before_enumeration(self) -> None:
        with (patch("modules.subdomain.resolve_provider_executable", return_value="amass"),
              patch("modules.subdomain.run_passive_provider", return_value=ProviderRunResult(
                  [], "completed", 0, diagnostics=("v5.1.1",))) as provider):
            result = run_amass("example.com")
        self.assertEqual(result.status, "failed")
        self.assertIn("Amass 5", result.reason)
        self.assertEqual(provider.call_count, 1)
        self.assertEqual(provider.call_args.args[2], ["amass", "-version"])

    def test_discovery_combinations_use_real_runner_and_merge_amass_graph(self) -> None:
        popen = subprocess.Popen
        for providers in (["subfinder"], ["amass"], ["subfinder", "amass"],
                          ["subfinder", "amass", "dnsx"]):
            with self.subTest(providers=providers), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "subdomains.txt"
                report = Path(directory) / "subdomains.json"

                def launch(command, **kwargs):
                    if "-version" in command:
                        script = "import sys; print('v4.2.0', file=sys.stderr)"
                    elif command[0] == "amass":
                        script = "print('api.example.com (FQDN) --> cname_record --> alias.example.com (FQDN)'); print('other.test (FQDN) --> a_record --> 192.0.2.1 (IPAddress)')"
                    elif command[0] == "dnsx":
                        # Candidates are persisted before resolution; final TXT is not candidates.
                        self.assertEqual((Path(directory)/'subdomains_candidates.txt').read_text().splitlines(),
                                         ['alias.example.com', 'api.example.com', 'www.example.com'])
                        script = "import sys; print(sys.stdin.read(), end='')"
                    else:
                        script = "print('www.example.com'); print('api.example.com')"
                    return popen([sys.executable, "-u", "-c", script], **kwargs)

                with (patch("modules.subdomain.shutil.which", side_effect=lambda name: name),
                      patch("modules.subdomain.subprocess.Popen", side_effect=launch)):
                    hylianscan.run_passive_subdomain_discovery(
                        "example.com", providers, output, report, quiet=True,
                    )
                expected = set()
                if "subfinder" in providers:
                    expected.update(['api.example.com', 'www.example.com'])
                if "amass" in providers:
                    expected.update(['api.example.com', 'alias.example.com'])
                self.assertEqual(output.read_text().splitlines(), sorted(expected))
                document = json.loads(report.read_text())
                self.assertTrue(all(p['status']=='completed' for p in document['providers']))

    def test_interrupt_checkpoints_candidates_and_dnsx_partial_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "subdomains.txt"
            report = Path(directory) / "subdomains.json"
            partial = ProviderRunResult(["api.example.com"], "interrupted", reason="Interrupted by user.",
                                        metadata=[{"host": "api.example.com"}])
            with (patch("hylianscan.run_subfinder", return_value=ProviderRunResult(
                    ["api.example.com", "www.example.com"], "completed", 0)),
                  patch("hylianscan.run_dnsx", side_effect=ProviderInterrupted(partial)),
                  self.assertRaises(KeyboardInterrupt)):
                hylianscan.run_passive_subdomain_discovery(
                    "example.com", ["subfinder", "dnsx"], output, report, quiet=True,
                )
            self.assertEqual(output.read_text().splitlines(), ["api.example.com"])
            self.assertEqual((Path(directory)/"subdomains_candidates.txt").read_text().splitlines(),
                             ["api.example.com", "www.example.com"])
            resolution = json.loads(report.read_text())["results"]["resolution"]
            self.assertEqual(resolution["status"], "interrupted")
            self.assertEqual(resolution["metadata"], partial.metadata)


if __name__ == "__main__":
    unittest.main()
