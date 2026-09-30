"""Offline benchmark checks; no namespaces, sudo, or public targets required."""

import copy
import csv
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from modules.json_exporter import build_tcp_scan_document
from modules.tcp_scanner import PortScanResult, ScanResult
from scripts import benchmark
from scripts.benchmark_services import banner, check_services
from tests.fixtures.mock_servers import get_closed_ephemeral_port


ROOT = Path(__file__).resolve().parents[1]


def options(*arguments):
    return benchmark.resolve_options(benchmark.parser().parse_args(list(arguments)))


def document(case):
    findings = tuple(PortScanResult(
        port=service["port"], service="unknown", banner=(None if service["kind"] == "silent"
                                                        else banner(service["port"])),
        response_time=0.001, address=benchmark.TARGET, address_family="ipv4",
    ) for service in case.services)
    return build_tcp_scan_document(ScanResult(
        target_host=benchmark.TARGET, resolved_ip=benchmark.TARGET,
        scanned_ports=len(case.ports), open_ports=findings, duration=0.1,
    ))


class BenchmarkTests(unittest.TestCase):
    def test_benchmark_selector_dispatches_profiles_and_rejects_unimplemented_modes(self):
        for arguments, profile in (([], "quick"), (["--benchmark", "tcp_scan"], "quick"),
                                   (["--benchmark", "tcp_scan", "--profile", "full"], "full")):
            with self.subTest(arguments=arguments):
                runner = MagicMock(return_value=17)
                with patch.dict(benchmark.BENCHMARKS, tcp_scan=runner):
                    self.assertEqual(benchmark.main(arguments), 17)
                runner.assert_called_once()
                args = runner.call_args.args[0]
                self.assertEqual(args.benchmark, "tcp_scan")
                self.assertEqual(args.profile, profile)
        help_text = benchmark.parser().format_help()
        self.assertIn("--benchmark {tcp_scan,subdomain}", help_text)
        self.assertIn("--profile {quick,full}", help_text)
        self.assertIn("default: quick", help_text)
        with tempfile.TemporaryDirectory() as directory, patch("sys.stderr"):
            with self.assertRaises(SystemExit) as rejection:
                benchmark.main(["--benchmark", "dnsx", "--output-dir", directory])
            self.assertEqual(rejection.exception.code, 2)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_profiles_include_dense_and_full_port_workloads_without_argument_overflow(self):
        cases = benchmark.scenarios(options("--profile", "full"))
        dense = next(case for case in cases if case.name == "scaling-open")
        full = next(case for case in cases if case.name == "scaling-all")
        self.assertEqual(len(dense.services), 256)
        self.assertTrue({service["port"] for service in dense.services} <= set(dense.ports))
        self.assertEqual(full.ports, list(range(1, 65536)))
        self.assertEqual(benchmark.port_expression(full.ports), "1-65535")
        self.assertEqual(benchmark.port_expression([1, 2, 4, 8, 9]), "1-2,4,8-9")
        for case in cases:
            self.assertEqual(len(case.ports), len(set(case.ports)))
        self.assertNotIn("scaling-all", [case.name for case in benchmark.scenarios(options())])

    def test_pilot_preserves_coverage_budget_overrides_and_full_repetition_count(self):
        args = options("--budget-seconds", "60", "--warmups", "0")
        cases = benchmark.scenarios(args)
        costs = {case.name: 4 for case in cases}
        calibration = benchmark.repetitions(args, cases, costs, 10)
        self.assertEqual(set(calibration["repetitions"]), set(costs))
        self.assertTrue(all(count >= 2 for count in calibration["repetitions"].values()))
        self.assertTrue(calibration["target_feasible"])
        args.fast_runs = 20
        overridden = benchmark.repetitions(args, cases, costs, 10)
        self.assertEqual(overridden["repetitions"]["sparse"], 20)
        self.assertFalse(overridden["target_feasible"])
        args = options("--profile", "full")
        cases = benchmark.scenarios(args)
        full = benchmark.repetitions(args, cases, {case.name: 1 for case in cases}, 0)
        self.assertEqual(full["repetitions"]["scaling-all"], 5)
        self.assertEqual(full["repetitions"]["mixed"], 10)
        self.assertEqual(full["repetitions"]["sparse"], 30)

    def test_validation_detects_missing_duplicates_unexpected_and_each_drop_port(self):
        for profile in ("quick", "full"):
            with self.subTest(profile=profile):
                case = next(case for case in benchmark.scenarios(options("--profile", profile)) if case.name == "mixed")
                good = document(case)
                counts = {port: 1 for port in case.filtered_ports}
                self.assertEqual(benchmark.validate_document(good, case, counts), [])
                incomplete = dict(counts)
                incomplete[case.filtered_ports[-1]] = 0
                errors = benchmark.validate_document(good, case, incomplete)
                self.assertTrue(any(str(case.filtered_ports[-1]) in error for error in errors))
        broken = copy.deepcopy(good)
        finding = broken["results"]["open_ports"][0]
        broken["results"]["open_ports"].append(copy.deepcopy(finding))
        extra = copy.deepcopy(finding)
        extra["port"] = 40000
        broken["results"]["open_ports"].append(extra)
        finding["banner"]["raw"] = "wrong"
        errors = benchmark.validate_document(broken, case, counts)
        self.assertTrue(any("Duplicate" in error for error in errors))
        self.assertTrue(any("Unexpected open" in error for error in errors))
        self.assertTrue(any("Incorrect banner" in error for error in errors))
        broken["results"]["open_ports"] = []
        self.assertTrue(any("Missing" in error for error in benchmark.validate_document(broken, case, counts)))

    def test_silent_findings_remain_open_and_no_timeout_state_is_invented(self):
        case = next(case for case in benchmark.scenarios(options()) if case.name == "silent")
        good = document(case)
        self.assertEqual(good["results"]["open_ports"][0]["status"], "open")
        self.assertEqual(benchmark.validate_document(good, case, {}), [])
        good["results"]["open_ports"][0]["banner"]["raw"] = "invented evidence"
        self.assertTrue(benchmark.validate_document(good, case, {}))

    def test_single_sample_resource_attribution_and_memory_capability(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hyperfine.json"
            result = {"times": [0.5], "user": 0.2, "system": 0.1, "exit_codes": [0],
                      "memory_usage_byte": [123456]}
            benchmark.write_json(path, {"results": [result]})
            self.assertEqual(benchmark.read_hyperfine(path)["peak_memory_bytes"], 123456)
            del result["memory_usage_byte"]
            benchmark.write_json(path, {"results": [result]})
            self.assertIsNone(benchmark.read_hyperfine(path)["peak_memory_bytes"])
            result["times"] = [0.5, 0.4]
            benchmark.write_json(path, {"results": [result]})
            with self.assertRaises(ValueError):
                benchmark.read_hyperfine(path)

    def test_failure_and_ctrl_c_clean_up_and_retain_sample_evidence(self):
        for failure in (RuntimeError("setup failure"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                args = options()
                case = benchmark.scenarios(args)[0]
                report = {"directory": directory, "samples": [], "validation": {}}
                lab = MagicMock()

                def fail_prepare():
                    (Path(report["samples"][0]["directory"]) / "services.json").write_text("incomplete JSON")
                    raise failure

                lab.prepare.side_effect = fail_prepare
                lab.close.side_effect = OSError("cleanup failure")
                with patch.object(benchmark, "Lab", return_value=lab):
                    with self.assertRaises(type(failure)):
                        benchmark.execute_sample(report, args, case, "candidate", ROOT, "measured", 1)
                lab.close.assert_called_once()
                saved = json.loads((Path(report["samples"][0]["directory"]) / "sample.json").read_text())
                self.assertIn(saved["status"], ("failed", "interrupted"))
                self.assertTrue(saved["cleanup_errors"])
                self.assertTrue(any("telemetry is invalid" in error for error in saved["validation_errors"]))
                self.assertGreaterEqual(saved["total_sample_seconds"], 0)

    def test_preflight_failure_retains_a_final_battery_report(self):
        for failure in (RuntimeError("Kali VM is off"), AttributeError("malformed tool metadata")):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory, patch.object(
                benchmark, "preflight", side_effect=failure
            ):
                self.assertEqual(benchmark.main(["--benchmark", "tcp_scan", "--output-dir", directory]), 1)
                report = json.loads(next(Path(directory).glob("*/report.json")).read_text())
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["benchmark"], "tcp_scan")
                self.assertEqual(report["profile"], "quick")
                self.assertEqual(report["samples"], [])
                self.assertFalse(report["validation"]["real_lab_executed"])
                self.assertGreaterEqual(report["total_battery_seconds"], 0)

    def test_cleanup_stops_both_namespaces_before_reaping_and_deleting(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = benchmark.Lab(Path(directory), {}, sys.executable)
            lab.namespaces = [lab.scanner, lab.target]
            lab.service_process = MagicMock()
            events = []
            stopped = set()

            def root(command, **_kwargs):
                events.append(command)
                output = ""
                if command[:3] == ["ip", "netns", "pids"] and command[3] not in stopped:
                    output = "101\n" if command[3] == lab.scanner else "102\n"
                if command[:2] == ["kill", "-TERM"]:
                    stopped.add(lab.scanner if command[-1] == "101" else lab.target)
                return subprocess.CompletedProcess(command, 0, output, "")

            lab.service_process.wait.side_effect = lambda **_kwargs: events.append(["wait"])
            with patch.object(lab, "root", side_effect=root):
                self.assertEqual(lab.close(), [])
            wait = events.index(["wait"])
            deletion = next(index for index, event in enumerate(events) if event[:3] == ["ip", "netns", "delete"])
            terms = [index for index, event in enumerate(events) if event[:2] == ["kill", "-TERM"]]
            self.assertEqual(len(terms), 2)
            self.assertLess(max(terms), wait)
            self.assertLess(wait, deletion)

    def test_reports_keep_total_battery_separate_from_scans_and_exclude_warmups(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = {"id": "one", "scenario": "sparse", "variant": "candidate", "role": "measured",
                      "status": "completed", "validation_errors": [], "cleanup_errors": [],
                      "metrics": {"execution_seconds": 0.3, "native_scan_seconds": 0.1,
                                  "cpu_user_seconds": 0.02, "cpu_system_seconds": 0.01,
                                  "peak_memory_bytes": 1000}}
            warmup = copy.deepcopy(sample)
            warmup.update(id="warmup", role="warmup")
            warmup["metrics"]["execution_seconds"] = 10
            report = {"directory": directory, "status": "completed", "benchmark": "tcp_scan", "profile": "quick",
                      "versions": {"candidate": {}}, "scenarios": [{"name": "sparse"}],
                      "samples": [sample, warmup]}
            benchmark.save_report(report, 12.5, None)
            self.assertEqual(report["total_battery_seconds"], 12.5)
            elapsed = next(row for row in report["summary"] if row["metric"] == "execution_seconds")
            self.assertEqual(elapsed["median"], 0.3)
            self.assertEqual(elapsed["count"], 1)
            with (Path(directory) / "battery.csv").open(newline="") as stream:
                battery = next(csv.DictReader(stream))
                self.assertEqual(battery["benchmark"], "tcp_scan")
                self.assertEqual(battery["profile"], "quick")
                self.assertEqual(battery["total_battery_seconds"], "12.5")
            report["status"] = "interrupted"
            benchmark.save_report(report, 13, None)
            self.assertEqual(json.loads((Path(directory) / "report.json").read_text())["status"], "interrupted")

    def test_correctness_failure_invalidates_a_faster_candidate_comparison(self):
        report = {"status": "failed", "versions": {"reference": {}, "candidate": {}},
                  "scenarios": [{"name": "sparse"}], "summary": [
                      {"scenario": "sparse", "variant": "reference", "metric": "execution_seconds", "median": 2},
                      {"scenario": "sparse", "variant": "candidate", "metric": "execution_seconds", "median": 1}]}
        comparison = benchmark.comparisons(report, 5)[0]
        self.assertFalse(comparison["valid"])
        self.assertIsNone(comparison["regressed"])

    def test_persistent_service_lab_handles_real_protocols_and_many_open_ports(self):
        """Exercise the real CLI/dispatcher on localhost, including an expired probe."""
        import socket

        def available(choices):
            for port in choices:
                with socket.socket() as listener:
                    try:
                        listener.bind(("127.0.0.1", port))
                    except OSError:
                        continue
                    return port
            self.skipTest("All registered unprivileged protocol ports are occupied.")

        http_port = available([8080, 8000, 8008, 8081, 8088])
        https_port = available([8443, 2053, 2083, 2087, 2096])
        ports = set()
        while len(ports) < 65:
            ports.add(get_closed_ephemeral_port())
        silent_port = ports.pop()
        services = [{"port": port, "kind": "banner"} for port in ports]
        services += [{"port": http_port, "kind": "http"}, {"port": https_port, "kind": "https"},
                     {"port": silent_port, "kind": "silent"}]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config = {"address": "127.0.0.1", "services": services, "timeout": 1,
                      "workers": 16, "delay_ms": 0, "filtered_ports": [],
                      "closed_check_port": get_closed_ephemeral_port()}
            path = directory / "lab.json"
            benchmark.write_json(path, config)
            with (directory / "server.log").open("w") as log:
                process = subprocess.Popen([sys.executable, str(ROOT / "scripts/benchmark_services.py"), str(path)],
                                           stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 10
                    while not (directory / "ready.json").exists():
                        if process.poll() is not None:
                            self.fail((directory / "server.log").read_text())
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.05)
                    self.assertTrue(check_services(config)["ready"])
                    command = [sys.executable, str(ROOT / "hylianscan.py"), "127.0.0.1", "--ipv4", "--quiet",
                               "--threads", "16", "--timeout", "1", "--ports",
                               ",".join(str(service["port"]) for service in services), "--json-output", "scan.json"]
                    result = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    output = json.loads((directory / "output/scan.json").read_text())
                    findings = {finding["port"]: finding for finding in output["results"]["open_ports"]}
                    self.assertEqual(set(findings), {service["port"] for service in services})
                    for port in ports:
                        self.assertEqual(findings[port]["banner"]["raw"], banner(port))
                    self.assertEqual(findings[http_port]["probe"]["name"], "http")
                    self.assertEqual(findings[https_port]["probe"]["name"], "https")
                    self.assertEqual(findings[https_port]["tls"]["certificate"]["fingerprints"]["sha256"],
                                     benchmark.CERTIFICATE_SHA256)
                    self.assertIsNone(findings[silent_port]["banner"]["raw"])
                    self.assertEqual(findings[silent_port]["status"], "open")
                finally:
                    (directory / "stop").touch()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            self.assertEqual(json.loads((directory / "services.json").read_text())["errors"], [])


if __name__ == "__main__":
    unittest.main()
