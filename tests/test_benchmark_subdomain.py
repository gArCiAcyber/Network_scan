"""Check the real passive CLI against offline subprocesses and independent sets."""

import copy
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts import benchmark as common
from scripts import benchmark_subdomain as bench


def options(*arguments):
    return common.resolve_options(common.parser().parse_args([
        "--benchmark", "subdomain", "--python", sys.executable, "--warmups", "0",
        "--fast-runs", "2", "--slow-runs", "2", "--provider-timeout", "1", *arguments]))


def report(directory, versions=None):
    return {"directory": str(directory), "benchmark": "subdomain", "status": "running",
            "versions": versions or {"candidate": {}}, "scenarios": bench.scenarios("quick"),
            "samples": [], "_started": time.perf_counter()}


class SubdomainBenchmarkTests(unittest.TestCase):
    def test_dispatch_and_profiles_keep_correctness_cases_and_scale_volume(self):
        for profile in ("quick", "full"):
            with self.subTest(profile=profile), patch.object(bench, "run_subdomain", return_value=17) as runner:
                self.assertEqual(common.main(["--benchmark", "subdomain", "--profile", profile]), 17)
                self.assertEqual(runner.call_args.args[0].profile, profile)
            cases = bench.scenarios(profile)
            self.assertTrue({"invalid-scope", "empty", "failure-partial", "timeout-partial"} <= {c["name"] for c in cases})
        self.assertEqual(bench.scenarios("quick")[3]["size"], 10_000)
        self.assertEqual(bench.scenarios("full")[3]["size"], 100_000)
        self.assertFalse(bench.in_scope("outside.test"))
        self.assertFalse(bench.in_scope("api.benchmark.test.evil.test"))
        self.assertFalse(bench.in_scope("bad..benchmark.test"))
        self.assertFalse(bench.in_scope("*.benchmark.test"))
        self.assertFalse(bench.in_scope(bench.DOMAIN))
        self.assertTrue(bench.in_scope("api.benchmark.test"))

    def test_real_cli_replays_overlap_empty_failure_and_timeout_without_tools(self):
        cases = [c for c in bench.scenarios("quick") if c["name"] in {
            "overlap", "empty", "failure-partial", "timeout-partial"}]
        with tempfile.TemporaryDirectory() as directory:
            battery = report(directory)
            for case in cases:
                with self.subTest(case=case["name"]):
                    sample = bench.execute_sample(common, battery, options(), case, "candidate", common.ROOT, "measured", 1)
                    self.assertEqual(sample["status"], "completed", sample)
                    sample_dir = Path(sample["directory"])
                    self.assertTrue((sample_dir / "subfinder.stdout.log").is_file())
                    self.assertTrue(json.loads((sample_dir / "worker.json").read_text())["provider_processes_reaped"])
                    ledger = [json.loads(line) for line in (sample_dir / "provider-commands.jsonl").read_text().splitlines()]
                    self.assertEqual([entry["provider"] for entry in ledger], ["subfinder", "amass"])
                    if case["name"] == "overlap":
                        self.assertEqual(sample["metrics"]["unique_in_scope"], 150)
                        self.assertEqual(sample["metrics"]["overlap"], 50)
                        self.assertEqual(sample["metrics"]["subfinder_exclusive"], 50)
                        self.assertEqual(sample["exit_code"], 0)
                    elif case["name"] == "empty":
                        self.assertEqual(sample["metrics"]["unique_in_scope"], 0)
                        self.assertEqual(sample["exit_code"], 0)
                    else:
                        self.assertEqual(sample["exit_code"], 1)
                        self.assertEqual(sample["providers"]["amass"]["status"], case["mode"])
                        self.assertGreater(sample["metrics"]["unique_in_scope"], 0)

    def test_scope_defects_are_reported_without_sanitizing_exported_evidence(self):
        case = next(c for c in bench.scenarios("quick") if c["name"] == "invalid-scope")
        with tempfile.TemporaryDirectory() as directory:
            battery = report(directory)
            sample = bench.execute_sample(common, battery, options(), case, "candidate", common.ROOT, "measured", 1)
            self.assertEqual(sample["status"], "failed")
            self.assertEqual(sample["metrics"]["invalid_or_out_of_scope"], 7)
            self.assertTrue(any("out-of-scope" in error for error in sample["validation_errors"]))
            text = (Path(sample["directory"]) / "evidence/subdomains.txt").read_text()
            self.assertIn("outside.test", text)
            self.assertIn("https://api.benchmark.test", text)

    def test_validation_detects_lost_names_and_changed_attribution(self):
        case = next(c for c in bench.scenarios("quick") if c["name"] == "overlap")
        with tempfile.TemporaryDirectory() as directory:
            sample = bench.execute_sample(common, report(directory), options(), case, "candidate", common.ROOT, "measured", 1)
            document = json.loads((Path(sample["directory"]) / "output/passive.json").read_text())
            text = (Path(sample["directory"]) / "evidence/subdomains.txt").read_text()
            expected = {name: bench.fixture_data(case, name) for name in case["providers"]}
            self.assertEqual(bench.validate_document(document, text, expected)[0], [])
            broken = copy.deepcopy(document)
            broken["results"]["subdomains"].pop()
            broken["results"]["sources"] = {}
            errors, _ = bench.validate_document(broken, text, expected)
            self.assertTrue(any("missing 1" in error for error in errors))
            self.assertTrue(any("attribution" in error for error in errors))

    def test_reference_modules_are_isolated_and_lost_results_invalidate_comparison(self):
        case = bench.scenarios("quick")[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "reference"
            checkout.mkdir()
            for name in ("core", "modules"):
                shutil.copytree(common.ROOT / name, checkout / name, ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copy2(common.ROOT / "hylianscan.py", checkout / "hylianscan.py")
            source = checkout / "modules/subdomain.py"
            source.write_text(source.read_text().replace("subdomains.append(subdomain)", "pass  # Deliberately lose evidence"))
            battery = report(directory, {"reference": {}, "candidate": {}})
            broken = bench.execute_sample(common, battery, options(), case, "reference", checkout, "measured", 1)
            good = bench.execute_sample(common, battery, options(), case, "candidate", common.ROOT, "measured", 1)
            self.assertEqual(broken["status"], "failed")
            self.assertEqual(good["status"], "completed", good)
            self.assertEqual(broken["workload_sha256"], good["workload_sha256"])
            battery["status"] = "failed"
            common.save_report(battery, 1, 5)
            self.assertTrue(all(not row["valid"] and row["regressed"] is None for row in battery["comparisons"]))

    def test_battery_alternates_versions_keeps_samples_and_excludes_partial_rankings(self):
        cases = [bench.scenarios("quick")[0], bench.scenarios("quick")[5]]
        for case in cases:
            case["size"] = 3
        with tempfile.TemporaryDirectory() as directory, patch.object(bench, "scenarios", return_value=cases):
            args = options("--output-dir", directory, "--reference", str(common.ROOT))
            self.assertEqual(bench.run_subdomain(args), 0)
            path = next(Path(directory).glob("*/report.json"))
            battery = json.loads(path.read_text())
            self.assertTrue(battery["validation"]["correctness_passed"])
            measured = [s for s in battery["samples"] if s["scenario"] == "subfinder" and s["role"] == "measured"]
            self.assertEqual([s["variant"] for s in measured], ["reference", "candidate", "candidate", "reference"])
            self.assertEqual(len({s["workload_sha256"] for s in measured}), 1)
            rankings = {row["scenario"]: row for row in battery["comparisons"]}
            self.assertTrue(rankings["subfinder"]["valid"])
            self.assertFalse(rankings["failure-partial"]["valid"])
            with (path.parent / "samples.csv").open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), len(battery["samples"]))
            self.assertIn("providers", rows[0])
            self.assertIn("subfinder_count", rows[0])
            self.assertNotIn("cpu_user_seconds", rows[0])

    def test_worker_timeout_and_interrupt_retain_sample_and_battery_reports(self):
        for failure in (subprocess.TimeoutExpired("fixture", 1), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                battery = report(directory)
                process = MagicMock()
                process.wait.side_effect = failure
                with patch.object(bench.subprocess, "Popen", return_value=process), patch.object(bench, "stop_worker") as stop:
                    if isinstance(failure, KeyboardInterrupt):
                        with self.assertRaises(KeyboardInterrupt):
                            bench.execute_sample(common, battery, options(), bench.scenarios("quick")[0], "candidate", common.ROOT, "measured", 1)
                    else:
                        bench.execute_sample(common, battery, options(), bench.scenarios("quick")[0], "candidate", common.ROOT, "measured", 1)
                stop.assert_called_once_with(process)
                saved = json.loads(next(Path(directory).glob("*/sample.json")).read_text())
                self.assertIn(saved["status"], ("failed", "interrupted"))
                self.assertTrue((Path(saved["directory"]) / "worker.log").exists())
                self.assertTrue((Path(directory) / "report.json").is_file())
        with tempfile.TemporaryDirectory() as directory, patch.object(bench, "execute_sample", side_effect=KeyboardInterrupt()):
            self.assertEqual(bench.run_subdomain(options("--output-dir", directory)), 130)
            saved = json.loads(next(Path(directory).glob("*/report.json")).read_text())
            self.assertEqual(saved["status"], "interrupted")
            self.assertFalse(saved["validation"]["battery_completed"])

    def test_cancellation_stops_real_fixtures_and_keeps_emitted_partial_evidence(self):
        case = next(c for c in bench.scenarios("quick") if c["name"] == "timeout-partial")
        real_popen = subprocess.Popen
        with tempfile.TemporaryDirectory() as directory:
            battery = report(directory)

            def launch(command, **kwargs):
                process = real_popen(command, **kwargs)
                if "--worker" not in command:
                    return process
                real_wait = process.wait
                interrupted = False

                def wait(timeout=None):
                    nonlocal interrupted
                    if interrupted:
                        return real_wait(timeout=timeout)
                    interrupted = True
                    path = Path(battery["samples"][0]["directory"])
                    deadline = time.monotonic() + 15
                    while not (path / "amass.stderr.log").exists():
                        if process.poll() is not None:
                            self.fail((path / "worker.log").read_text())
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.025)
                    raise KeyboardInterrupt

                process.wait = wait
                return process

            with patch.object(bench.subprocess, "Popen", side_effect=launch), self.assertRaises(KeyboardInterrupt):
                bench.execute_sample(common, battery, options("--provider-timeout", "30"), case,
                                     "candidate", common.ROOT, "measured", 1)
            sample = battery["samples"][0]
            path = Path(sample["directory"])
            self.assertEqual(sample["status"], "interrupted")
            self.assertEqual(sample["cleanup_errors"], [])
            self.assertIn("host1.benchmark.test", (path / "amass.stdout.log").read_text())
            self.assertEqual(json.loads((path / "subfinder.result.json").read_text())["status"], "completed")
            pids = [json.loads(line)["pid"] for line in (path / "provider-commands.jsonl").read_text().splitlines()]
            for pid in pids:
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


if __name__ == "__main__":
    unittest.main()
