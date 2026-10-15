"""Exercise the real passive CLI, saved evidence, and benchmark correctness gate."""

import copy
import csv
import errno
import json
import os
import pstats
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from benchmarks import cli as common
from benchmarks import subdomain as bench


def options(*arguments):
    return common.resolve_options(common.parser().parse_args([
        "--benchmark", "subdomain", "--python", sys.executable, "--warmups", "0",
        "--fast-runs", "2", "--slow-runs", "2", "--provider-timeout", "30", *arguments]))


def report(directory, cases=None, versions=None):
    return {"directory": str(directory), "benchmark": "subdomain", "status": "running",
            "versions": versions or {"candidate": {}}, "scenarios": cases or bench.scenarios("quick"),
            "samples": [], "_started": time.perf_counter()}


def case_named(name):
    return next(case for case in bench.scenarios("full") if case["name"] == name)


class SubdomainBenchmarkTests(unittest.TestCase):
    def test_kernel_exit_notification_reaps_without_timed_wait(self):
        process = MagicMock(returncode=None, pid=123, args=["worker"])
        process.wait.return_value = 7
        with (patch.object(bench.os, "pidfd_open", return_value=19, create=True) as opener,
              patch.object(bench.os, "close") as close,
              patch.object(bench.selectors, "DefaultSelector") as selector,
              patch.object(bench.time, "monotonic", side_effect=[100, 100.02])):
            completion = selector.return_value.__enter__.return_value
            completion.select.return_value = [("exit", 1)]
            self.assertEqual(bench.wait_for_worker(process, .5), (7, "linux_pidfd"))
            opener.assert_called_once_with(123)
            completion.register.assert_called_once_with(19, bench.selectors.EVENT_READ)
            completion.select.assert_called_once()
            self.assertAlmostEqual(completion.select.call_args.args[0], .48)
            process.wait.assert_called_once_with()
            close.assert_called_once_with(19)

    def test_kernel_wait_timeout_and_interruption_close_descriptor(self):
        for failure in (None, KeyboardInterrupt()):
            with self.subTest(failure=failure):
                process = MagicMock(returncode=None, pid=123, args=["worker"])
                with (patch.object(bench.os, "pidfd_open", return_value=19, create=True),
                      patch.object(bench.os, "close") as close,
                      patch.object(bench.selectors, "DefaultSelector") as selector):
                    completion = selector.return_value.__enter__.return_value
                    completion.select.return_value = []
                    completion.select.side_effect = failure
                    with self.assertRaises(KeyboardInterrupt if failure else subprocess.TimeoutExpired) as caught:
                        bench.wait_for_worker(process, .5)
                    if failure is None:
                        self.assertEqual(caught.exception.cmd, ["worker"])
                        self.assertEqual(caught.exception.timeout, .5)
                    process.wait.assert_not_called()
                    close.assert_called_once_with(19)

    def test_wait_fallback_and_resource_exhaustion(self):
        for unavailable in (None, OSError(errno.ENOSYS, "unsupported"), OSError(errno.EPERM, "blocked")):
            with self.subTest(unavailable=unavailable):
                process = MagicMock(returncode=None, pid=123, args=["worker"])
                process.wait.return_value = 0
                opener = None if unavailable is None else MagicMock(side_effect=unavailable)
                with (patch.object(bench.os, "pidfd_open", opener, create=True),
                      patch.object(bench.time, "monotonic", side_effect=[100, 100.02])):
                    self.assertEqual(bench.wait_for_worker(process, .5), (0, "popen_wait"))
                    process.wait.assert_called_once()
                    self.assertAlmostEqual(process.wait.call_args.kwargs["timeout"], .48)
        process = MagicMock(returncode=None, pid=123)
        with patch.object(bench.os, "pidfd_open", side_effect=OSError(errno.EMFILE, "fds exhausted"), create=True):
            with self.assertRaises(OSError):
                bench.wait_for_worker(process, .5)
            process.wait.assert_not_called()
        process.returncode = 7
        self.assertEqual(bench.wait_for_worker(process, .5), (7, "already_exited"))

    def test_real_worker_wait_preserves_exit_and_deadline(self):
        for code, timeout, expected in (("raise SystemExit(7)", 5, 7), ("import time; time.sleep(60)", .02, None)):
            with self.subTest(expected=expected):
                process = subprocess.Popen([sys.executable, "-c", code])
                try:
                    if expected is None:
                        with self.assertRaises(subprocess.TimeoutExpired):
                            bench.wait_for_worker(process, timeout)
                    else:
                        exit_code, method = bench.wait_for_worker(process, timeout)
                        self.assertEqual(exit_code, expected)
                        self.assertIn(method, ("linux_pidfd", "popen_wait", "already_exited"))
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)

    def test_minimal_observation_preserves_oracles_and_workload(self):
        with tempfile.TemporaryDirectory() as directory:
            battery = report(directory)
            case = case_named("baseline-1k")
            detailed = bench.execute_sample(common, battery, options(), case, "candidate", common.ROOT, "measured", 1)
            minimal = bench.execute_sample(common, battery, options("--passive-observations", "minimal"),
                                           case, "candidate", common.ROOT, "measured", 2)
            self.assert_saved_sample(detailed, case)
            self.assert_saved_sample(minimal, case)
            self.assertEqual(detailed["workload_sha256"], minimal["workload_sha256"])
            self.assertEqual(minimal["observations_effective"], "minimal")
            self.assertIsNone(minimal["metrics"]["json_build_seconds"])
            self.assertIsNone(minimal["metrics"]["accepted_unique"])
            calls = json.loads((Path(minimal["directory"]) / "runner-results.json").read_text())
            self.assertTrue(calls)
            self.assertTrue(all("subdomains" not in entry["result"] for entry in calls))

    def test_minimal_faults_keep_detailed_injections(self):
        with tempfile.TemporaryDirectory() as directory:
            case = case_named("writer-error")
            sample = bench.execute_sample(common, report(directory), options("--passive-observations", "minimal"),
                                          case, "candidate", common.ROOT, "measured", 1)
            self.assert_saved_sample(sample, case)
            self.assertEqual(sample["observations_effective"], "detailed")
            self.assertEqual(sample["expected_exit_code"], 1)

    @unittest.skipUnless(sys.platform == "linux", "Resource companions require Linux")
    def test_resource_observation_modes_and_companion_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            battery = report(directory)
            case = case_named("baseline-1k")
            args = options("--resources", "--diagnostic-profile", "--passive-observations", "minimal")
            detailed = bench.execute_sample(common, battery, args, case, "candidate", common.ROOT, "resources", 1)
            self.assert_saved_sample(detailed, case)
            self.assertEqual(detailed["observations_effective"], "detailed")
            stats = pstats.Stats(str(Path(detailed["directory"]) / "cli.prof"))
            self.assertTrue(any(key[2] == "build_subdomain_discovery_document" for key in stats.stats))
            args.reference = common.ROOT
            args.reference_observations = "detailed"
            minimal = bench.execute_sample(common, battery, args, case, "candidate", common.ROOT, "resources", 2)
            self.assert_saved_sample(minimal, case)
            self.assertEqual(minimal["observations_effective"], "minimal")
            self.assertTrue(minimal["diagnostic_profile"])

    def test_observation_options_reject_invalid_comparisons(self):
        for arguments in (["--passive-observations", "minimal"], ["--diagnostic-profile"],
                          ["--benchmark", "subdomain", "--reference-observations", "minimal"]):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                common.resolve_options(common.parser().parse_args(arguments))

    def test_observation_comparison_rejects_different_product_hashes_before_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            args = options("--reference", str(common.ROOT), "--reference-observations", "detailed",
                           "--passive-observations", "minimal", "--scenario", "baseline-1k",
                           "--output-dir", directory)
            with patch.object(common, "source_metadata", side_effect=[{"source_sha256": "a"}, {"source_sha256": "b"}]), \
                    patch.object(bench, "execute_sample") as execute:
                self.assertEqual(bench.run_subdomain(args), 1)
                execute.assert_not_called()
            saved = json.loads(next(Path(directory).glob("*/report.json")).read_text())
            self.assertIn("identical product snapshots", saved["error"])

    @unittest.skipUnless(sys.platform == "linux", "Resource companions require Linux")
    def test_profile_write_failure_still_reaps_owned_children(self):
        real_resource_command = common.resource_command

        def inject_failure(args, output, command):
            shim = ("import sys; from pathlib import Path; from unittest.mock import patch; "
                    f"sys.path.insert(0, {str(common.ROOT)!r}); "
                    "from benchmarks.subdomain import worker; "
                    "failure=patch('cProfile.Profile.dump_stats', side_effect=OSError('profile disk fault')); "
                    "failure.start(); raise SystemExit(worker(Path(sys.argv[1]), Path(sys.argv[2])))")
            return real_resource_command(args, output, [args.python, "-c", shim, *command[-2:]])

        with tempfile.TemporaryDirectory() as directory, patch.object(common, "resource_command", side_effect=inject_failure):
            sample = bench.execute_sample(common, report(directory), options("--resources", "--diagnostic-profile"),
                                          case_named("baseline-1k"), "candidate", common.ROOT, "resources", 1)
            self.assertEqual(sample["status"], "failed")
            worker_record = json.loads((Path(sample["directory"]) / "worker.json").read_text())
            self.assertTrue(worker_record["provider_processes_reaped"])
            self.assertTrue(any("profile disk fault" in error for error in worker_record["cleanup_errors"]))

    def test_cli_profile_preserves_information_command(self):
        with tempfile.TemporaryDirectory() as directory:
            target = str(common.ROOT / "hylianscan.py")
            original = subprocess.run([sys.executable, target, "--version"], capture_output=True, text=True)
            output = Path(directory) / "stages.json"
            profiled = subprocess.run([sys.executable, str(common.ROOT / "benchmarks/cli_profile.py"),
                                      "--output", str(output), "--", target, "--version"], capture_output=True, text=True)
            self.assertEqual((profiled.returncode, profiled.stdout, profiled.stderr),
                             (original.returncode, original.stdout, original.stderr))
            events = json.loads(output.read_text())["events"]
            self.assertTrue(any(event["stage"] == "imports" and event["event"] == "end" for event in events))
            self.assertTrue(output.with_suffix(".prof").is_file())

    def assert_processes_stopped(self, entries):
        for pid in {entry["pid"] for entry in entries}:
            if os.name == "nt":
                import ctypes
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.OpenProcess.restype = ctypes.c_void_p
                kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
                kernel.CloseHandle.argtypes = [ctypes.c_void_p]
                handle = kernel.OpenProcess(0x1000, False, pid)
                if handle:
                    try:
                        exit_code = ctypes.c_ulong()
                        self.assertTrue(kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)))
                        self.assertNotEqual(exit_code.value, 259, f"Fixture {pid} remains active")
                    finally:
                        kernel.CloseHandle(handle)
            else:
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)

    def assert_saved_sample(self, sample, case):
        self.assertIn(sample["process_wait_method"], ("linux_pidfd", "popen_wait", "already_exited"))
        directory = Path(sample["directory"])
        if sample["status"] != "completed":
            retained = Path(tempfile.mkdtemp(prefix="hylianscan-failed-test-")) / directory.name
            shutil.copytree(directory, retained)
            self.fail(f"Unexpected sample failure: {sample}; evidence retained at {retained}")
        self.assertEqual(sample["cleanup_errors"], [])
        self.assertEqual(sample["validation_errors"], [])
        self.assertEqual(sample["observed_exit_code"], sample["expected_exit_code"])
        document = json.loads((directory / "output/passive.json").read_text(encoding="utf-8"))
        text = (directory / "evidence/subdomains.txt").read_text(encoding="utf-8")
        expected = {provider: bench.fixture_data(case, provider) for provider in case["providers"]}
        wanted = sorted({name for data in expected.values() for name in data["expected"]})
        self.assertEqual(document["results"]["subdomains"], wanted)
        self.assertEqual(document["results"]["candidates"]["subdomains"], wanted)
        self.assertEqual(text, "\n".join(wanted) + "\n")
        self.assertEqual(bench.validate_document(document, text, expected)[0], [])
        journals = list((directory / "evidence").glob("subdomains_observed_*.tsv"))
        self.assertEqual(len(journals), 1)
        observed = {name: set() for name in case["providers"]}
        for line in journals[0].read_text(encoding="utf-8").splitlines():
            provider, hostname = line.split("\t")
            observed[provider].add(hostname)
        self.assertEqual(observed, {name: set(data["accepted_expected"]) for name, data in expected.items()})
        worker = json.loads((directory / "worker.json").read_text(encoding="utf-8"))
        self.assertTrue(worker["provider_processes_reaped"])
        ledger = [json.loads(line) for line in (directory / "provider-commands.jsonl").read_text(
            encoding="utf-8").splitlines()]
        self.assert_processes_stopped(ledger)
        self.assertTrue((directory / "expected.json").is_file())
        self.assertTrue((directory / "runner-results.json").is_file())
        return document, worker, ledger

    def test_dispatch_profiles_and_exact_union_loads(self):
        self.assertEqual(bench.DOMAIN, "hylianlab.test")
        self.assertEqual(common.parser().parse_args(["--benchmark", "subdomain"]).profile, "quick")
        for profile in ("quick", "full"):
            with self.subTest(profile=profile), patch.object(bench, "run_subdomain", return_value=17) as runner:
                self.assertEqual(common.main(["--benchmark", "subdomain", "--profile", profile]), 17)
                self.assertEqual(runner.call_args.args[0].profile, profile)
            names = {case["name"] for case in bench.scenarios(profile)}
            self.assertTrue({"baseline-1k", "baseline-10k", "invalid-scope", "stream-pressure",
                             "sigint-subfinder", "sigint-amass", "sigint-save", "writer-error"} <= names)
            self.assertEqual("baseline-100k" in names, profile == "full")
        for size, name in ((1000, "baseline-1k"), (10_000, "baseline-10k"), (100_000, "baseline-100k")):
            case = case_named(name)
            a, b = (set(bench.fixture_data(case, provider)["expected"]) for provider in ("subfinder", "amass"))
            self.assertEqual((len(a), len(b), len(a & b), len(a | b)),
                             (size * 7 // 10, size * 6 // 10, size * 3 // 10, size))
            self.assertIn(bench.DOMAIN, a & b)
            self.assertIn("api.dev.europa.hylianlab.test", a | b)

    def test_all_1k_scenarios_save_exact_evidence_and_reap_every_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            battery = report(directory)
            for case in (case for case in bench.scenarios("quick") if case["size"] <= 1000):
                with self.subTest(case=case["name"]):
                    sample = bench.execute_sample(common, battery, options(), case, "candidate", common.ROOT, "measured", 1)
                    document, worker, ledger = self.assert_saved_sample(sample, case)
                    providers = {item["name"]: item for item in document["providers"]}
                    name = case["name"]
                    self.assertEqual(sample["comparison_eligible"], case["mode"] == "completed")
                    self.assertEqual(sample["metrics"]["invalid_or_out_of_scope"], 0)
                    if case["mode"] == "completed" and case["size"]:
                        count = 1000 if len(case["providers"]) == 2 else 700 if "subfinder" in providers else 600
                        self.assertEqual(sample["metrics"]["unique_in_scope"], count)
                        self.assertIn(bench.DOMAIN, document["results"]["subdomains"])
                    if name == "baseline-1k":
                        self.assertEqual((sample["metrics"]["subfinder_count"], sample["metrics"]["amass_count"],
                                          sample["metrics"]["overlap"], sample["metrics"]["subfinder_exclusive"],
                                          sample["metrics"]["amass_exclusive"]), (700, 600, 300, 400, 300))
                        amass = [entry for entry in ledger if entry["provider"] == "amass"]
                        self.assertEqual([entry["stage"] for entry in amass],
                                         ["version", "help", "help", "version", "engine", "enum", "subs"])
                        self.assertNotIn(["enum", "-h"], [entry["arguments"] for entry in amass])
                        enum, subs = (next(entry["arguments"] for entry in amass if entry["stage"] == stage)
                                      for stage in ("enum", "subs"))
                        self.assertIn("-passive", enum)
                        self.assertIn("-names", subs)
                        self.assertEqual(enum[enum.index("-dir") + 1], subs[subs.index("-dir") + 1])
                        self.assertTrue((Path(subs[subs.index("-dir") + 1]) / "laboratory-graph.jsonl").is_file())
                        for value in worker["metrics"]["first_candidate_seconds"].values():
                            self.assertGreater(value, 0)
                    if name == "amass4-1k":
                        self.assertEqual(ledger[-1]["arguments"], ["enum", "-passive", "-d", bench.DOMAIN])
                    if name == "invalid-scope":
                        self.assertTrue(any("outside.test" in Path(entry["stdout"]).read_text(encoding="utf-8")
                                            for entry in ledger if entry["data_stage"]))
                        self.assertNotIn("outside.test", document["results"]["subdomains"])
                    if case.get("duplicates"):
                        self.assertGreater(sample["metrics"]["emitted_records"]["subfinder"], 7000)
                    if name == "stream-pressure":
                        self.assertGreater(sample["metrics"]["emitted_stdout_bytes"], 65536)
                        self.assertGreater(sample["metrics"]["emitted_stderr_bytes"], 65536)
                    if name in {"failure-partial", "abrupt-partial", "timeout-partial"}:
                        self.assertEqual(providers["subfinder"]["count"], 700)
                        self.assertEqual(providers["amass"]["count"], 120)
                        self.assertEqual(providers["amass"]["status"], "timed_out" if name == "timeout-partial" else "failed")
                        self.assertEqual(providers["amass"]["exit_code"], None if name == "timeout-partial" else 9 if name == "abrupt-partial" else 7)
                    if name in {"empty", "failure-empty", "timeout-empty"}:
                        self.assertEqual(document["results"]["subdomains"], [])
                        self.assertTrue(all(value is None for value in worker["metrics"]["first_candidate_seconds"].values()))
                    if name.startswith("sigint-"):
                        self.assertEqual(sample["observed_exit_code"], 130)
                        self.assertTrue(any(event.get("received") and event["signal"] == "SIGINT" for event in worker["signals"]))
                        self.assertTrue(any(event.get("requested") for event in worker["signals"]))
                        if name != "sigint-save":
                            active = "subfinder" if name == "sigint-subfinder" else "amass"
                            self.assertEqual(providers[active]["status"], "interrupted")
                            self.assertEqual(providers[active]["count"], 120)
                        else:
                            self.assertEqual(len(document["results"]["subdomains"]), 1000)
                    if name == "writer-error":
                        self.assertEqual(sample["observed_exit_code"], 1)
                        self.assertEqual(providers["amass"]["status"], "skipped")
                        self.assertEqual(len(document["results"]["subdomains"]), 700)
                        self.assertEqual(worker["metrics"]["accepted_unique"]["amass"], 600)
                        self.assertIn("Injected laboratory TXT writer failure", (Path(sample["directory"]) / "worker.log").read_text())

    def test_validation_rejects_lost_results_extra_names_and_changed_attribution(self):
        case = case_named("subfinder-1k")
        with tempfile.TemporaryDirectory() as directory:
            sample = bench.execute_sample(common, report(directory), options(), case, "candidate", common.ROOT, "measured", 1)
            document, _, _ = self.assert_saved_sample(sample, case)
            text = (Path(sample["directory"]) / "evidence/subdomains.txt").read_text()
            expected = {"subfinder": bench.fixture_data(case, "subfinder")}
            broken = copy.deepcopy(document)
            broken["results"]["subdomains"].pop()
            broken["results"]["sources"] = {}
            errors, _ = bench.validate_document(broken, text, expected)
            self.assertTrue(any("missing 1" in error for error in errors))
            self.assertTrue(any("attribution" in error for error in errors))
            broken = copy.deepcopy(document)
            broken["results"]["subdomains"].append("outside.test")
            errors, _ = bench.validate_document(broken, text, expected)
            self.assertTrue(any("unexpected 1" in error for error in errors))
            self.assertTrue(any("out-of-scope" in error for error in errors))

    def test_isolated_reference_losing_names_invalidates_performance_comparison(self):
        case = case_named("subfinder-1k")
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory) / "reference"
            checkout.mkdir()
            for name in ("core", "modules"):
                shutil.copytree(common.ROOT / name, checkout / name, ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copy2(common.ROOT / "hylianscan.py", checkout / "hylianscan.py")
            source = checkout / "modules/subdomain.py"
            original = source.read_text(encoding="utf-8")
            self.assertIn("seen.add(hostname)", original)
            source.write_text(original.replace("seen.add(hostname)", "pass  # Deliberately lose accepted evidence"), encoding="utf-8")
            battery = report(directory, [case], {"reference": {}, "candidate": {}})
            broken = bench.execute_sample(common, battery, options(), case, "reference", checkout, "measured", 1)
            good = bench.execute_sample(common, battery, options(), case, "candidate", common.ROOT, "measured", 1)
            self.assertEqual(broken["status"], "failed")
            self.assertTrue(any("missing" in error for error in broken["validation_errors"]))
            self.assert_saved_sample(good, case)
            self.assertEqual(broken["workload_sha256"], good["workload_sha256"])
            battery["status"] = "failed"
            common.save_report(battery, 1, 5)
            self.assertTrue(all(not row["valid"] and row["regressed"] is None for row in battery["comparisons"]))

    def test_small_battery_alternates_versions_and_exports_json_csv_without_fault_rankings(self):
        cases = [case_named("subfinder-1k"), case_named("failure-empty")]
        with tempfile.TemporaryDirectory() as directory, patch.object(bench, "scenarios", return_value=cases):
            self.assertEqual(bench.run_subdomain(options("--output-dir", directory, "--reference", str(common.ROOT))), 0)
            path = next(Path(directory).glob("*/report.json"))
            battery = json.loads(path.read_text())
            self.assertTrue(battery["validation"]["correctness_passed"])
            measured = [sample for sample in battery["samples"] if sample["scenario"] == "subfinder-1k" and sample["role"] == "measured"]
            self.assertEqual([sample["variant"] for sample in measured], ["reference", "candidate", "candidate", "reference"])
            self.assertEqual(len({sample["workload_sha256"] for sample in measured}), 1)
            rankings = {row["scenario"]: row for row in battery["comparisons"]}
            self.assertTrue(rankings["subfinder-1k"]["valid"])
            self.assertFalse(rankings["failure-empty"]["valid"])
            with (path.parent / "samples.csv").open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), len(battery["samples"]))
            for field in ("providers", "subfinder_count", "expected_exit_code", "observed_exit_code", "cli_command"):
                self.assertIn(field, rows[0])
            self.assertIn(bench.DOMAIN, json.loads(rows[0]["cli_command"]))

    def test_explicit_scenario_selection_and_unexpected_worker_abort_preserve_reports(self):
        args = options("--scenario", "subfinder-1k", "--scenario", "failure-empty")
        self.assertEqual(args.subdomain_scenarios, ["subfinder-1k", "failure-empty"])
        with self.assertRaisesRegex(ValueError, "Unknown scenario"):
            bench.run_subdomain(options("--scenario", "baseline-100k"))
        for failure in (subprocess.TimeoutExpired("fixture", 1), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                battery = report(directory)
                process = MagicMock()
                with (patch.object(bench.subprocess, "Popen", return_value=process),
                      patch.object(bench, "wait_for_worker", side_effect=failure),
                      patch.object(bench, "stop_worker") as stop):
                    if isinstance(failure, KeyboardInterrupt):
                        with self.assertRaises(KeyboardInterrupt):
                            bench.execute_sample(common, battery, options(), case_named("subfinder-1k"), "candidate", common.ROOT, "measured", 1)
                    else:
                        bench.execute_sample(common, battery, options(), case_named("subfinder-1k"), "candidate", common.ROOT, "measured", 1)
                stop.assert_called_once_with(process, Path(battery["samples"][0]["directory"]))
                saved = json.loads(next(Path(directory).glob("*/sample.json")).read_text())
                self.assertIn(saved["status"], ("failed", "interrupted"))
                self.assertTrue((Path(saved["directory"]) / "worker.log").exists())
                self.assertTrue((Path(directory) / "report.json").is_file())
        with tempfile.TemporaryDirectory() as directory, patch.object(bench, "execute_sample", side_effect=KeyboardInterrupt()):
            self.assertEqual(bench.run_subdomain(options("--output-dir", directory)), 130)
            saved = json.loads(next(Path(directory).glob("*/report.json")).read_text())
            self.assertEqual(saved["status"], "interrupted")
            self.assertFalse(saved["validation"]["battery_completed"])

    def test_watchdog_cleans_owned_children_after_worker_exit_without_touching_reused_pids(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            entries = [{"pid": 101, "process_identity": "owned-birth"},
                       {"pid": 202, "process_identity": "old-birth"},
                       {"pid": 303, "process_identity": None}]
            (directory / "launches.jsonl").write_text("\n".join(json.dumps(entry) for entry in entries))
            identities = {101: ["owned-birth", None], 202: ["different-birth"]}
            process = MagicMock()
            process.poll.return_value = 0
            with (patch.object(bench, "process_identity", side_effect=lambda pid: identities[pid].pop(0)),
                  patch.object(bench.os, "getpgid", return_value=101, create=True),
                  patch.object(bench.os, "killpg", create=True) as kill,
                  patch.object(bench.subprocess, "run") as terminate):
                bench.stop_worker(process, directory)
            process.send_signal.assert_not_called()
            if os.name == "nt":
                terminate.assert_called_once()
                self.assertEqual(terminate.call_args.args[0], ["taskkill", "/PID", "101", "/T", "/F"])
                kill.assert_not_called()
            else:
                kill.assert_called_once_with(101, signal.SIGKILL)
                terminate.assert_not_called()

    def test_outer_cancellation_saves_real_subfinder_prefix_and_leaves_no_children(self):
        case = {**case_named("timeout-partial"), "providers": ["subfinder"]}
        with tempfile.TemporaryDirectory() as directory:
            battery = report(directory)
            def wait(process, timeout):
                path = Path(battery["samples"][0]["directory"])
                deadline = time.monotonic() + 20
                while True:
                    journals = list((path / "evidence").glob("subdomains_observed_*.tsv"))
                    if journals and len(journals[0].read_text(encoding="utf-8").splitlines()) == 120:
                        raise KeyboardInterrupt
                    if process.poll() is not None:
                        self.fail((path / "worker.log").read_text())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.01)

            with patch.object(bench, "wait_for_worker", side_effect=wait), self.assertRaises(KeyboardInterrupt):
                bench.execute_sample(common, battery, options(), case, "candidate", common.ROOT, "measured", 1)
            sample = battery["samples"][0]
            path = Path(sample["directory"])
            self.assertEqual(sample["status"], "interrupted")
            self.assertEqual(sample["cleanup_errors"], [])
            wanted = bench.fixture_data(case, "subfinder")["accepted_expected"]
            document = json.loads((path / "output/passive.json").read_text(encoding="utf-8"))
            self.assertEqual(document["results"]["subdomains"], wanted)
            self.assertEqual(document["providers"][0]["status"], "interrupted")
            self.assertEqual((path / "evidence/subdomains.txt").read_text(encoding="utf-8"),
                             "\n".join(wanted) + "\n")
            ledger = [json.loads(line) for line in (path / "provider-commands.jsonl").read_text().splitlines()]
            self.assert_processes_stopped(ledger)

    def test_abrupt_worker_loss_cleans_its_separate_provider_and_retains_evidence(self):
        case = {**case_named("timeout-partial"), "providers": ["subfinder"]}
        real_wait = bench.wait_for_worker
        with tempfile.TemporaryDirectory() as directory:
            battery = report(directory)
            orphan_identity = []
            def wait(process, timeout):
                path = Path(battery["samples"][0]["directory"])
                deadline = time.monotonic() + 20
                while True:
                    journals = list((path / "evidence").glob("subdomains_observed_*.tsv"))
                    if journals and len(journals[0].read_text(encoding="utf-8").splitlines()) == 120:
                        break
                    if process.poll() is not None:
                        self.fail((path / "worker.log").read_text())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(.01)
                ledger = [json.loads(line) for line in (path / "launches.jsonl").read_text().splitlines()]
                provider = ledger[-1]
                process.kill()  # Kill only the worker, leaving its provider alive.
                result = real_wait(process, timeout)
                orphan_identity.append(bench.process_identity(provider["pid"]))
                return result

            with patch.object(bench, "wait_for_worker", side_effect=wait):
                sample = bench.execute_sample(common, battery, options(), case, "candidate", common.ROOT, "measured", 1)
            self.assertIsNotNone(orphan_identity[0])
            self.assertEqual(sample["status"], "failed")
            self.assertEqual(sample["cleanup_errors"], [])
            path = Path(sample["directory"])
            saved = json.loads((path / "sample.json").read_text())
            self.assertEqual(saved["status"], "failed")
            self.assertTrue((path / "worker.log").exists())
            self.assertTrue((path / "expected.json").exists())
            ledger = [json.loads(line) for line in (path / "provider-commands.jsonl").read_text().splitlines()]
            self.assert_processes_stopped(ledger)


if __name__ == "__main__":
    unittest.main()
