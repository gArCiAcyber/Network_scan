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
from modules.provider_compatibility import PROVIDERS
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

    @patch("hylianscan.inspect_provider_compatibility", return_value={"status": "tested"})
    def test_provider_diagnostics_are_hidden_by_default_and_shown_when_verbose(self, compatibility) -> None:
        for verbose in (False, True):
            with self.subTest(verbose=verbose), tempfile.TemporaryDirectory() as temporary_dir:
                output = io.StringIO()

                def run_provider(domain, telemetry_callback, **kwargs):
                    telemetry_callback("Subfinder stderr: source detail")
                    return ProviderRunResult(["www.example.com"], "completed", 0)

                with (
                    patch("hylianscan.run_subfinder", side_effect=run_provider),
                    redirect_stdout(output),
                ):
                    hylianscan.run_passive_subdomain_discovery(
                        "example.com", ["subfinder"], Path(temporary_dir) / "subdomains.txt",
                        provider_paths={"subfinder": sys.executable},
                        verbose=verbose,
                    )

                self.assertEqual("source detail" in output.getvalue(), verbose)

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

    def test_run_dnsx_validates_installation_then_skips_without_candidates(self) -> None:
        with (
            patch("modules.subdomain.shutil.which", return_value="dnsx") as resolver,
            patch("modules.subdomain.run_passive_provider") as provider,
        ):
            result = run_dnsx([])

        self.assertEqual(result, ProviderRunResult([], "skipped", reason="No candidate subdomains to resolve."))
        resolver.assert_called_once_with("dnsx")
        provider.assert_not_called()

    def test_run_dnsx_rejects_missing_installation_without_candidates(self) -> None:
        with (
            patch("modules.subdomain.shutil.which", return_value=None),
            self.assertRaisesRegex(ValueError, "DNSx executable was not found.*--dnsx-path"),
        ):
            run_dnsx([])

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

    @patch("hylianscan.inspect_provider_compatibility", return_value={"status": "tested"})
    def test_passive_discovery_forwards_provider_paths(self, compatibility) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_path = Path(temporary_dir) / "subdomains.txt"

            with (
                patch("modules.subdomain.shutil.which", return_value=None) as lookup,
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
                        "subfinder": sys.executable,
                        "amass": sys.executable,
                    },
                    quiet=True,
                )

        self.assertIn("Raw Discoveries: 2", summary)
        self.assertIn("Unique Subdomains: 2", summary)
        self.assertEqual(
            subfinder.call_args.kwargs["executable_path"],
            sys.executable,
        )
        self.assertEqual(amass.call_args.kwargs["executable_path"], sys.executable)
        lookup.assert_not_called()

    def test_cli_rejects_unavailable_tools_before_any_provider_starts(self) -> None:
        for unavailable in ("subfinder", "amass", "dnsx"):
            for path_kind in ("PATH", "missing", "directory"):
                for quiet in (False, True):
                    with self.subTest(tool=unavailable, path=path_kind, quiet=quiet), \
                            tempfile.TemporaryDirectory() as directory:
                        output = Path(directory) / "subdomains.txt"
                        report = Path(directory) / "subdomains.json"
                        for path in (output, report):
                            path.write_text("existing evidence", encoding="utf-8")
                        argv = ["hylianscan", "example.test", "-s", "-a", "--dnsx",
                                "--output", directory, "--json-output", "subdomains.json"]
                        if quiet:
                            argv.append("--quiet")
                        if path_kind != "PATH":
                            argv.extend([f"--{unavailable}-path", str(
                                Path(directory) / "missing" if path_kind == "missing"
                                else Path(directory))])
                        terminal = io.StringIO()
                        with (
                            patch("sys.argv", argv),
                            patch("modules.subdomain.shutil.which", side_effect=lambda name:
                                  None if name == unavailable else name),
                            patch("hylianscan.resolve_subdomain_json_output_path", return_value=report),
                            patch("hylianscan.clear_screen"),
                            patch("hylianscan.show_banner"),
                            patch("hylianscan.PassiveDiscoveryDisplay") as display,
                            patch("hylianscan.run_subfinder") as subfinder,
                            patch("hylianscan.run_amass") as amass,
                            patch("hylianscan.run_dnsx") as dnsx,
                            redirect_stdout(terminal),
                            self.assertRaises(SystemExit) as context,
                        ):
                            hylianscan.main()
                        self.assertEqual(context.exception.code, 1)
                        self.assertIn(f"--{unavailable}-path", terminal.getvalue())
                        self.assertIn("executable", terminal.getvalue())
                        for operation in (subfinder, amass, dnsx, display):
                            operation.assert_not_called()
                        for path in (output, report):
                            self.assertEqual(path.read_text(encoding="utf-8"), "existing evidence")
                        self.assertEqual(set(Path(directory).iterdir()), {output, report})

    @patch("hylianscan.inspect_provider_compatibility", return_value={"status": "tested"})
    def test_preflight_requires_only_selected_tools(self, compatibility) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("modules.subdomain.shutil.which", side_effect=lambda name:
                  name if name == "subfinder" else None) as lookup,
            patch("hylianscan.run_subfinder", return_value=ProviderRunResult([], "completed", 0)) as run,
        ):
            hylianscan.run_passive_subdomain_discovery(
                "example.test", ["subfinder"], Path(directory) / "subdomains.txt", quiet=True,
            )
        lookup.assert_called_once_with("subfinder")
        run.assert_called_once()

    @patch("hylianscan.inspect_provider_compatibility", return_value={"status": "tested"})
    def test_cli_writes_partial_reports_before_provider_failure_exit(self, compatibility) -> None:
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
                patch("hylianscan.resolve_provider_executable"),
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

    def test_provider_carriage_returns_do_not_join_records(self) -> None:
        messages = []
        script = (
            "import sys,time; "
            "sys.stdout.buffer.write(b'api.example.com\\r'); sys.stdout.flush(); "
            "sys.stderr.buffer.write(b'first warning\\r'); sys.stderr.flush(); "
            "time.sleep(.1); "
            "sys.stdout.buffer.write(b'\\nwww.example.com\\rlast.example.com'); "
            "sys.stderr.buffer.write(b'\\nsecond warning\\rfinal warning')"
        )
        result = run_passive_provider("example.com", "Fake",
                                      [sys.executable, "-u", "-c", script],
                                      telemetry_callback=messages.append)
        self.assertEqual(result.subdomains, ["api.example.com", "last.example.com", "www.example.com"])
        self.assertEqual(result.diagnostics, ("first warning", "second warning", "final warning"))
        self.assertTrue(any("3 candidates" in message for message in messages))

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

    @patch("hylianscan.inspect_provider_compatibility", return_value={"status": "tested"})
    def test_cli_interrupt_saves_provider_evidence_and_exits_130(self, compatibility) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(target="example.com", output=None, json_output=None,
                                      quiet=True, subfinder=True, amass=False, dnsx=False)
            output = Path(directory) / "subdomains.txt"
            partial = ProviderRunResult(["api.example.com"], "interrupted", diagnostics=("source timeout",))
            with (patch("hylianscan.parse_arguments", return_value=args),
                  patch("hylianscan.resolve_provider_executable"),
                  patch("hylianscan.resolve_subdomain_output_path", return_value=output),
                  patch("hylianscan.run_subfinder", side_effect=ProviderInterrupted(partial)),
                  redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as context):
                hylianscan.main()
            self.assertEqual(context.exception.code, 130)
            self.assertEqual(output.read_text().splitlines(), ["api.example.com"])
            self.assertIn("source timeout", (Path(directory)/"subdomains_providers.log").read_text())

    def test_amass_v5_reads_isolated_graph_and_stops_owned_engine(self) -> None:
        popen = subprocess.Popen
        commands = []
        engines = []
        graph_directories = []
        messages = []

        def launch(command, **kwargs):
            commands.append(command)
            if "-version" in command:
                script = "print('v5.0.0')"
            elif command[1] == "engine":
                environment = kwargs["env"]
                graph_directories.append(Path(environment["APPDATA" if os.name == "nt"
                                                          else "XDG_CONFIG_HOME"]) / "amass")
                script = "import time; print('engine diagnostic', flush=True); time.sleep(30)"
            elif command[1] == "enum":
                config = Path(command[command.index("-config") + 1])
                self.assertIn("active: false", config.read_text())
                # Model v5's engine-side default graph location, not enum's -dir.
                (graph_directories[0] / "names.txt").write_text(
                    "api.example.com\nelsewhere.test\n", encoding="utf-8")
                # pb/v3 writes adjacent bars with no CR/LF to non-terminal stderr.
                # Split a frame across reads, then exceed the runner's 64 KiB chunks.
                bar = "0 / 1 [" + "_" * 80 + "] 0.00% ? p/s"
                script = (
                    "import sys,time; "
                    f"sys.stderr.write({bar[:35]!r}); sys.stderr.flush(); time.sleep(.1); "
                    f"sys.stderr.write({bar[35:]!r} + {bar!r} * 12000); "
                    "sys.stderr.write('source unavailable\\n'); "
                    "sys.stderr.write('1 / 2 [==>___] 50.00% 12.34 p/s'); "
                    "sys.stderr.write('final warning'); print('www.example.com')"
                )
            else:
                graph = Path(command[command.index("-dir") + 1]) / "names.txt"
                script = f"from pathlib import Path; print(Path({str(graph)!r}).read_text())"
            process = popen([sys.executable, "-u", "-c", script], **kwargs)
            if command[1] == "engine":
                engines.append(process)
            return process

        def stop_engine(process):
            process.terminate()
            process.wait(timeout=5)

        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.yaml"
            config.write_text("options:\n  active: false\n", encoding="utf-8")
            with (patch("modules.subdomain.resolve_provider_executable", return_value="amass"),
                  patch("modules.subdomain._amass_engine_ready", side_effect=[False, True]),
                  patch("modules.subdomain._amass_v5_config", return_value=config),
                  patch("modules.subdomain.subprocess.Popen", side_effect=launch),
                  patch("modules.subdomain.stop_provider", side_effect=stop_engine) as stop):
                result = run_amass("example.com", telemetry_callback=messages.append)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.subdomains, ["api.example.com", "www.example.com"])
        self.assertEqual([command[1] for command in commands], ["-version", "engine", "enum", "subs"])
        self.assertEqual(commands[2][commands[2].index("-dir") + 1],
                         commands[3][commands[3].index("-dir") + 1])
        self.assertEqual(Path(commands[3][commands[3].index("-dir") + 1]), graph_directories[0])
        self.assertFalse(graph_directories[0].exists())
        stop.assert_any_call(engines[0])
        self.assertIsNotNone(engines[0].poll())
        self.assertIn("source unavailable", result.diagnostics)
        self.assertIn("final warning", result.diagnostics)
        self.assertIn("Amass engine output: engine diagnostic", result.diagnostics)
        self.assertNotIn("p/s", "\n".join([*messages, *result.diagnostics]))
        self.assertTrue(any("count pending graph query" in message for message in messages))
        self.assertFalse(any(message.startswith("Amass progress:") and "0 candidates" in message
                             for message in messages))

    def test_amass_v5_rejects_active_config(self) -> None:
        from modules.subdomain import _amass_v5_config

        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.yaml"
            config.write_text("options:\n  active: true\n", encoding="utf-8")
            with patch.dict(os.environ, {"AMASS_CONFIG": str(config)}), \
                    self.assertRaisesRegex(ValueError, "active enumeration"):
                _amass_v5_config()
            config.write_text("options: {active: false}\n", encoding="utf-8")
            with patch.dict(os.environ, {"AMASS_CONFIG": str(config)}):
                self.assertEqual(_amass_v5_config(), config.resolve())
            with patch.dict(os.environ, {"AMASS_CONFIG": str(config), "AMASS_DB_USER": "test"}), \
                    self.assertRaisesRegex(ValueError, "environment overrides"):
                _amass_v5_config()
            config.write_text("options:\n  bruteforce:\n    enabled: true\n", encoding="utf-8")
            with patch.dict(os.environ, {"AMASS_CONFIG": str(config)}), \
                    self.assertRaisesRegex(ValueError, "bruteforce"):
                _amass_v5_config()
            config.write_text("options:\n  database: 'postgres://example.invalid/test'\n", encoding="utf-8")
            with patch.dict(os.environ, {"AMASS_CONFIG": str(config)}), \
                    self.assertRaisesRegex(ValueError, "external engine or database"):
                _amass_v5_config()

    def test_amass_v5_queries_partial_graph_after_timeout(self) -> None:
        from modules.subdomain import _run_amass_v5

        engine = unittest.mock.Mock()
        engine.poll.return_value = None
        enumeration = ProviderRunResult([], "timed_out", reason="Timed out after 1 seconds.")
        names = ProviderRunResult(["api.example.com"], "completed", 0)

        def provider(domain, label, command, **kwargs):
            if command[1] == "enum":
                directory = Path(command[command.index("-dir") + 1])
                (directory / "amass_engine_test.log").write_text(
                    "old record\n" * 5000 + "\033[31mengine source timeout\033[0m\n", encoding="utf-8")
                (directory / "session-test.log").write_text("session diagnostic\n", encoding="utf-8")
                return enumeration
            return names

        with (patch("modules.subdomain._amass_engine_ready", side_effect=[False, True]),
              patch("modules.subdomain._amass_v5_config", return_value=Path("config.yaml")),
              patch("modules.subdomain.subprocess.Popen", return_value=engine),
              patch("modules.subdomain.run_passive_provider", side_effect=provider) as run,
              patch("modules.subdomain.stop_provider") as stop):
            result = _run_amass_v5("example.com", "amass", 1, None)
        self.assertEqual(result.status, "timed_out")
        self.assertEqual(result.subdomains, ["api.example.com"])
        self.assertEqual(run.call_count, 2)
        stop.assert_called_once_with(engine)
        self.assertIn("Amass amass_engine_test.log: engine source timeout", result.diagnostics)
        self.assertIn("Amass session-test.log: session diagnostic", result.diagnostics)
        self.assertEqual(len(result.diagnostics), 21)
        with (patch("modules.subdomain._amass_engine_ready", side_effect=[False, True]),
              patch("modules.subdomain._amass_v5_config", return_value=Path("config.yaml")),
              patch("modules.subdomain.subprocess.Popen", return_value=engine),
              patch("modules.subdomain.run_passive_provider", side_effect=[
                  ProviderRunResult(["www.example.com"], "completed", 0),
                  ValueError("Unable to start Amass results"),
              ]), patch("modules.subdomain.stop_provider") as stop):
            result = _run_amass_v5("example.com", "amass", 1, None)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.subdomains, ["www.example.com"])
        stop.assert_called_once_with(engine)

    def test_amass_v5_does_not_reuse_or_stop_an_existing_engine(self) -> None:
        from modules.subdomain import _run_amass_v5

        with (patch("modules.subdomain._amass_engine_ready", return_value=True),
              patch("modules.subdomain._amass_v5_config", return_value=Path("config.yaml")),
              patch("modules.subdomain.subprocess.Popen") as launch,
              patch("modules.subdomain.run_passive_provider") as run,
              patch("modules.subdomain.stop_provider") as stop):
            result = _run_amass_v5("example.com", "amass", 1, None)
        self.assertEqual(result.status, "failed")
        self.assertIn("already running", result.reason)
        launch.assert_not_called()
        run.assert_not_called()
        stop.assert_not_called()

    def test_amass_v5_interrupt_keeps_graph_names_and_reaps_engine(self) -> None:
        from modules.subdomain import _run_amass_v5

        engine = unittest.mock.Mock()
        partial = ProviderRunResult([], "interrupted", reason="Interrupted by user.",
                                    diagnostics=("source warning",))
        with (patch("modules.subdomain._amass_engine_ready", side_effect=[False, True]),
              patch("modules.subdomain._amass_v5_config", return_value=Path("config.yaml")),
              patch("modules.subdomain.subprocess.Popen", return_value=engine),
              patch("modules.subdomain.run_passive_provider", side_effect=[
                  ProviderInterrupted(partial), ProviderRunResult(["api.example.com"], "completed", 0),
              ]), patch("modules.subdomain.stop_provider") as stop,
              self.assertRaises(ProviderInterrupted) as context):
            _run_amass_v5("example.com", "amass", 1, None)
        self.assertEqual(context.exception.result.status, "interrupted")
        self.assertEqual(context.exception.result.subdomains, ["api.example.com"])
        self.assertIn("source warning", context.exception.result.diagnostics)
        stop.assert_called_once_with(engine)

    def test_discovery_combinations_use_real_runner_and_merge_amass_graph(self) -> None:
        popen = subprocess.Popen
        for providers in (["subfinder"], ["amass"], ["subfinder", "amass"],
                          ["subfinder", "amass", "dnsx"]):
            with self.subTest(providers=providers), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "subdomains.txt"
                report = Path(directory) / "subdomains.json"

                def launch(command, **kwargs):
                    if "-version" in command:
                        script = f"import sys; print({PROVIDERS[command[0]]['baseline']!r}, file=sys.stderr)"
                    elif "-h" in command:
                        script = f"print({' '.join(PROVIDERS[command[0]]['required_flags'])!r})"
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

    @patch("hylianscan.inspect_provider_compatibility", return_value={"status": "tested"})
    def test_interrupt_checkpoints_candidates_and_dnsx_partial_metadata(self, compatibility) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "subdomains.txt"
            report = Path(directory) / "subdomains.json"
            partial = ProviderRunResult(["api.example.com"], "interrupted", reason="Interrupted by user.",
                                        metadata=[{"host": "api.example.com"}])
            with (patch("hylianscan.run_subfinder", return_value=ProviderRunResult(
                    ["api.example.com", "www.example.com"], "completed", 0)),
                  patch("hylianscan.resolve_provider_executable"),
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
