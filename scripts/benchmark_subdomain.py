"""Offline passive benchmark, with isolated CLI workers and subprocess fixtures.

Only executable resolution, provider launch, and their deadline are adapted.
Candidate parsing, result types, CLI orchestration, and writers execute unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import runpy
import signal
import subprocess
import sys
import time
import traceback
import uuid
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[1]
DOMAIN = "benchmark.test"
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


def scenarios(profile: str) -> list[dict]:
    def case(name, providers, size, mode="completed"):
        return {"name": name, "providers": providers, "size": size, "mode": mode,
                "slow": mode == "timed_out", "comparison_eligible": mode == "completed"}

    both = ["subfinder", "amass"]
    return [case("subfinder", ["subfinder"], 100), case("amass", ["amass"], 100),
            case("overlap", both, 100), case("scaling", both, 10_000 if profile == "quick" else 100_000),
            case("empty", both, 0), case("failure-partial", both, 3, "failed"),
            case("timeout-partial", both, 3, "timed_out"), case("invalid-scope", both, 3, "dirty")]


def fixture_data(case: dict, provider: str) -> dict:
    start = case["size"] // 2 if provider == "amass" else 0
    expected = sorted(f"host{index}.{DOMAIN}" for index in range(start, start + case["size"]))
    lines = list(expected)
    if lines:
        lines += [lines[0].upper() + ".", "\x1b[32m" + lines[-1] + "\x1b[0m"]
    lines += ["", "no-name", "provider status message"]
    if case["mode"] == "dirty":
        lines += ["outside.test", f"api.{DOMAIN}.evil.test", f"bad..{DOMAIN}",
                  f"-bad.{DOMAIN}", f"https://api.{DOMAIN}", f"*.{DOMAIN}", DOMAIN]
    status = case["mode"] if provider == "amass" and case["mode"] in {"failed", "timed_out"} else "completed"
    return {"lines": lines, "expected": expected, "status": status,
            "exit_code": {"completed": 0, "failed": 7, "timed_out": None}[status],
            # Exercise concurrent stderr draining beyond typical pipe capacity.
            "stderr": ("fixture diagnostic\n" * 8192 if case["name"] == "scaling" else "fixture diagnostic\n")}


def in_scope(name: str) -> bool:
    """Independent oracle: strict descendant, ASCII DNS hostname, no wildcard."""
    return (isinstance(name, str) and len(name) <= 253 and name.endswith("." + DOMAIN)
            and all(LABEL.fullmatch(label) for label in name.split(".")))


def fixture(path: Path) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    with path.with_suffix(".stdout.log").open("w", encoding="utf-8") as log:
        for offset in range(0, len(data["lines"]), 256):
            chunk = "\n".join(data["lines"][offset:offset + 256]) + "\n"
            sys.stdout.write(chunk)
            sys.stdout.flush()
            log.write(chunk)
            log.flush()
    sys.stderr.write(data["stderr"])
    sys.stderr.flush()
    path.with_suffix(".stderr.log").write_text(data["stderr"], encoding="utf-8")
    if data["status"] == "timed_out":
        time.sleep(3600)  # The real provider runner must terminate this fixture.
    return data["exit_code"] or 0


def stop_worker(process: subprocess.Popen) -> None:
    """Let the worker retain evidence and reap its fixtures before escalation."""
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=10)


def worker(checkout: Path, manifest: Path) -> int:
    # A fresh process imports only this checkout's implementation, even when the
    # harness itself lives in the candidate checkout or has imported its modules.
    sys.path.insert(0, str(checkout))
    import ssl  # Initialize SSLSocket before the offline socket guard.
    from modules import subdomain

    config = json.loads(manifest.read_text(encoding="utf-8"))
    directory = manifest.parent
    real_popen = subprocess.Popen
    real_runner = subdomain.run_passive_provider
    children = []
    commands = directory / "provider-commands.jsonl"

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    for signum in (signal.SIGINT, signal.SIGTERM, *([signal.SIGBREAK] if os.name == "nt" else [])):
        signal.signal(signum, interrupt)

    def launch(command, **kwargs):
        provider = command[0].removeprefix("offline-")
        expected = (["offline-subfinder", "-d", DOMAIN, "-silent"] if provider == "subfinder" else
                    ["offline-amass", "enum", "-passive", "-d", DOMAIN])
        if provider not in config["providers"] or command != expected:
            raise ValueError(f"Unexpected offline provider command: {command!r}")
        actual = [sys.executable, "-u", str(SCRIPT), "--fixture", str(directory / f"{provider}.json")]
        process = real_popen(actual, **kwargs)
        children.append(process)
        with commands.open("a", encoding="utf-8") as log:
            log.write(json.dumps({"provider": provider, "requested": command, "executed": actual,
                                  "pid": process.pid}) + "\n")
        return process

    def observe(*args, **kwargs):
        kwargs["timeout"] = config["provider_timeout"]
        result = real_runner(*args, **kwargs)
        name = kwargs["provider_name"].lower()
        (directory / f"{name}.result.json").write_text(json.dumps(asdict(result)), encoding="utf-8")
        return result

    sys.argv = [str(checkout / "hylianscan.py"), DOMAIN, "--quiet", "--output", "evidence",
                "--json-output", "passive.json", *("--" + name for name in config["providers"])]
    exit_code = 0
    try:
        with (patch.object(subdomain, "resolve_provider_executable",
                           side_effect=lambda provider_name, **_: "offline-" + provider_name.lower()),
              patch.object(subdomain, "run_passive_provider", side_effect=observe),
              patch.object(subprocess, "Popen", side_effect=launch),
              patch("socket.socket", side_effect=AssertionError("Offline benchmark attempted socket creation")),
              patch("socket.getaddrinfo", side_effect=AssertionError("Offline benchmark attempted DNS resolution"))):
            runpy.run_path(str(checkout / "hylianscan.py"), run_name="__main__")
    except SystemExit as error:
        exit_code = error.code if isinstance(error.code, int) else (1 if error.code else 0)
    except KeyboardInterrupt:
        exit_code = 130
    except Exception:
        traceback.print_exc()
        exit_code = 1
    finally:
        for signum in (signal.SIGINT, signal.SIGTERM, *([signal.SIGBREAK] if os.name == "nt" else [])):
            signal.signal(signum, signal.SIG_IGN)
        for child in children:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        (directory / "worker.json").write_text(json.dumps({"exit_code": exit_code,
            "provider_processes_reaped": all(child.poll() is not None for child in children)}), encoding="utf-8")
    return exit_code


def validate_document(document: dict, text: str, expected: dict) -> tuple[list[str], dict]:
    """Check raw exported evidence; never filter it to make validation pass."""
    errors = []

    def check_names(label, observed, wanted):
        if not isinstance(observed, list) or any(not isinstance(name, str) for name in observed):
            errors.append(f"{label}: expected a list of names")
            return set()
        actual = set(observed)
        missing, unexpected = wanted - actual, actual - wanted
        if missing or unexpected:
            errors.append(f"{label}: missing {len(missing)}, unexpected {len(unexpected)}; "
                          f"examples={sorted(missing | unexpected)[:8]}")
        if observed != sorted(actual):
            errors.append(f"{label}: duplicate or unsorted names")
        return actual

    wanted_sources = {}
    providers = document.get("providers", [])
    if not isinstance(providers, list) or any(not isinstance(item, dict) for item in providers):
        raise ValueError("Invalid providers document")
    by_provider = {item.get("name"): item for item in providers}
    if len(by_provider) != len(providers) or set(by_provider) != set(expected):
        errors.append("Provider inventory differs from the fixture")
    counts, observed_sets, statuses = {}, {}, {}
    for name, data in expected.items():
        wanted = set(data["expected"])
        for host in wanted:
            wanted_sources.setdefault(host, []).append(name)
        result = by_provider.get(name, {})
        observed = check_names(name, result.get("subdomains"), wanted)
        observed_sets[name] = {host for host in observed if in_scope(host)}
        counts[name] = len(observed)
        statuses[name] = {key: result.get(key) for key in ("status", "exit_code", "reason")}
        if result.get("count") != len(observed) or result.get("role") != "discovery":
            errors.append(f"{name}: incorrect count or provider role")
        if result.get("status") != data["status"] or result.get("exit_code") != data["exit_code"]:
            errors.append(f"{name}: incorrect completion status or exit code")
        if data["status"] != "completed" and not result.get("reason"):
            errors.append(f"{name}: partial results lack an error reason")
        if data["status"] == "completed" and result.get("reason") is not None:
            errors.append(f"{name}: completed provider has an unexpected error reason")
    wanted_sources = {host: sorted(names) for host, names in wanted_sources.items()}
    wanted = set(wanted_sources)
    results = document.get("results", {})
    actual = check_names("final", results.get("subdomains"), wanted)
    candidates = results.get("candidates", {})
    check_names("candidates", candidates.get("subdomains"), wanted)
    if results.get("sources") != wanted_sources or candidates.get("sources") != wanted_sources:
        errors.append("Provider attribution differs from expected sources")
    if text != "\n".join(sorted(wanted)) + "\n":
        errors.append("TXT output differs from the exact expected names")
    if document.get("discovery", {}).get("target", {}).get("domain") != DOMAIN:
        errors.append("Incorrect discovery domain")
    summary = document.get("discovery", {}).get("summary", {})
    if summary.get("providers") != len(expected) or summary.get("deduplicated_subdomains") != len(actual):
        errors.append("Discovery summary differs from provider/final findings")
    scoped = {host for host in actual if in_scope(host)}
    if actual - scoped:
        errors.append(f"Invalid/out-of-scope exported names: {sorted(actual - scoped)[:8]}")
    a, b = observed_sets.get("subfinder", set()), observed_sets.get("amass", set())
    return errors, {"providers": statuses, "metrics": {
        "unique_in_scope": len(scoped), "invalid_or_out_of_scope": len(actual - scoped),
        "subfinder_count": counts.get("subfinder", 0), "amass_count": counts.get("amass", 0),
        "overlap": len(a & b), "subfinder_exclusive": len(a - b), "amass_exclusive": len(b - a)}}


def execute_sample(common, report, args, case, variant, checkout, role, index):
    started = time.perf_counter()
    directory = Path(report["directory"]) / f"{len(report['samples']):04d}-{case['name']}-{variant}-{role}-{index}"
    directory.mkdir()
    expected = {name: fixture_data(case, name) for name in case["providers"]}
    manifest = {"domain": DOMAIN, "providers": case["providers"], "provider_timeout": args.provider_timeout}
    common.write_json(directory / "fixture.json", manifest)
    for name, data in expected.items():
        common.write_json(directory / f"{name}.json", data)
    workload_hash = hashlib.sha256(json.dumps({"manifest": manifest, "data": expected}, sort_keys=True).encode()).hexdigest()
    command = [args.python, str(SCRIPT), "--worker", str(checkout), str(directory / "fixture.json")]
    sample = {"id": directory.name, "directory": str(directory), "scenario": case["name"], "variant": variant,
              "role": role, "index": index, "command": command, "cwd": str(directory),
              "workload_sha256": workload_hash, "status": "running", "validation_errors": [],
              "cleanup_errors": [], "providers": {}, "metrics": {}, "comparison_eligible": case["comparison_eligible"]}
    report["samples"].append(sample)
    common.write_json(directory / "sample.json", sample)
    common.save_report(report, time.perf_counter() - report["_started"], args.regression_percent)
    process = None
    caught = None
    print(f"[{role}] {case['name']}: {variant}, sample {index}", flush=True)
    try:
        with (directory / "worker.log").open("w", encoding="utf-8") as log:
            group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
            execution_started = time.perf_counter()
            process = subprocess.Popen(command, cwd=directory, stdout=log, stderr=log, **group)
            sample["exit_code"] = process.wait(timeout=args.run_timeout)
        sample["metrics"] = {"execution_seconds": time.perf_counter() - execution_started,
                             "measurement_source": "stdlib_perf_counter"}
        wanted_exit = 1 if any(data["status"] != "completed" for data in expected.values()) else 0
        if sample["exit_code"] != wanted_exit:
            sample["validation_errors"].append(f"CLI exit {sample['exit_code']}, expected {wanted_exit}")
        document = json.loads((directory / "output/passive.json").read_text(encoding="utf-8"))
        text = (directory / "evidence/subdomains.txt").read_text(encoding="utf-8")
        errors, observations = validate_document(document, text, expected)
        sample["validation_errors"].extend(errors)
        sample["providers"] = observations["providers"]
        sample["metrics"].update(observations["metrics"])
        ledger = [json.loads(line) for line in (directory / "provider-commands.jsonl").read_text(encoding="utf-8").splitlines()]
        if [entry["provider"] for entry in ledger] != case["providers"]:
            sample["validation_errors"].append("Provider launch order differs from the fixture")
        for name, data in expected.items():
            checkpoint = json.loads((directory / f"{name}.result.json").read_text(encoding="utf-8"))
            if checkpoint["status"] != data["status"] or checkpoint["subdomains"] != next(
                    item["subdomains"] for item in document["providers"] if item["name"] == name):
                sample["validation_errors"].append(f"{name}: runner checkpoint differs from the report")
        if not json.loads((directory / "worker.json").read_text(encoding="utf-8"))["provider_processes_reaped"]:
            sample["cleanup_errors"].append("Fixture processes were not reaped")
        sample["status"] = "failed" if sample["validation_errors"] or sample["cleanup_errors"] else "completed"
    except KeyboardInterrupt as error:
        sample["status"] = "interrupted"
        caught = error
    except Exception as error:
        sample["status"] = "failed"
        sample["error"] = f"{type(error).__name__}: {error}"
    finally:
        previous = {s: signal.signal(s, signal.SIG_IGN) for s in (signal.SIGINT, signal.SIGTERM)}
        try:
            if process is not None:
                try:
                    stop_worker(process)
                except (OSError, subprocess.SubprocessError) as error:
                    sample["cleanup_errors"].append(str(error))
                    if sample["status"] != "interrupted":
                        sample["status"] = "failed"
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
        sample["total_sample_seconds"] = time.perf_counter() - started
        common.write_json(directory / "sample.json", sample)
    if caught is not None:
        raise caught
    return sample


def run_subdomain(args: argparse.Namespace) -> int:
    from scripts import benchmark as common
    args = common.resolve_options(args)
    cases = scenarios(args.profile)
    timestamp = common.build_timestamp() + "_" + uuid.uuid4().hex[:8]
    directory = (args.output_dir.resolve() / timestamp if args.output_dir else
                 common.resolve_output_workspace("benchmark", timestamp=timestamp))
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": {"name": "hylianscan_benchmark", "version": 1}, "benchmark": "subdomain",
              "mode": "offline", "profile": args.profile, "directory": str(directory), "started_utc": timestamp,
              "status": "running", "options": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
              "versions": {}, "scenarios": cases, "samples": [],
              "validation": {"battery_completed": False, "correctness_passed": None},
              "scope_policy": "ASCII DNS hostnames strictly below benchmark.test; apex, wildcards and URLs rejected",
              "timing_policy": "Worker launch through exit, including bootstrap, fixture subprocesses, evidence logging, CLI and reports; fixture preparation and validation excluded",
              "limitations": ["Fixtures do not verify real provider compatibility or discovery coverage",
                              "No live discovery, DNSx, HTTPx, first-candidate, CPU or memory measurements"],
              "_started": time.perf_counter()}
    variants = [("reference", args.reference), ("candidate", args.candidate)] if args.reference else [("candidate", args.candidate)]

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    previous = {s: signal.signal(s, interrupt) for s in (signal.SIGINT, signal.SIGTERM)}
    exit_code = 0
    try:
        report["environment"] = {"platform": platform.platform(), "kernel": platform.release(),
            "architecture": platform.machine(), "cpu_count": os.cpu_count(), "python_executable": args.python,
            "python": common.run([args.python, "--version"]).stdout.strip(), "cwd": str(Path.cwd()),
            "external_providers": "Not used; executable resolution and launch replaced with offline fixtures"}
        report["harness_sha256"] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in (SCRIPT, ROOT / "scripts/benchmark.py")}
        report["versions"] = {name: common.source_metadata(checkout) for name, checkout in variants}
        common.save_report(report, time.perf_counter() - report["_started"], args.regression_percent)
        costs = {}
        for case in cases:
            costs[case["name"]] = sum(execute_sample(common, report, args, case, name, checkout, "pilot", 0)["total_sample_seconds"]
                                     for name, checkout in variants)
        report["calibration"] = common.repetitions(args, [SimpleNamespace(**case) for case in cases], costs,
                                                   time.perf_counter() - report["_started"])
        report["calibration"]["note"] = "Pilot costs include worker setup, validation and cleanup; at least two measured samples per case/version"
        for case in cases:
            for index in range(args.warmups):
                for name, checkout in variants:
                    execute_sample(common, report, args, case, name, checkout, "warmup", index + 1)
            for index in range(report["calibration"]["repetitions"][case["name"]]):
                order = variants if index % 2 == 0 else list(reversed(variants))
                for name, checkout in order:
                    execute_sample(common, report, args, case, name, checkout, "measured", index + 1)
        report["validation"]["battery_completed"] = True
        report["validation"]["correctness_passed"] = all(sample["status"] == "completed" for sample in report["samples"])
        report["status"] = "completed" if report["validation"]["correctness_passed"] else "failed"
        if report["status"] == "failed":
            report["error"] = "Correctness failed; retained evidence invalidates performance comparisons"
            exit_code = 1
    except KeyboardInterrupt:
        report["status"], report["error"], exit_code = "interrupted", "Interrupted; collected evidence retained", 130
    except Exception as error:
        report["status"], report["error"], exit_code = "failed", f"{type(error).__name__}: {error}", 1
    finally:
        for signum in previous:
            signal.signal(signum, signal.SIG_IGN)
        try:
            started = report.pop("_started")
            common.save_report(report, time.perf_counter() - started, args.regression_percent)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    if any(row["regressed"] is True for row in report["comparisons"]):
        report["performance_regression"] = True
        common.save_report(report, time.perf_counter() - started, args.regression_percent)
        exit_code = 2
    print(f"Offline subdomain battery {report['status']}: {report['total_battery_seconds']:.1f}s. Reports: {directory}")
    return exit_code


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--fixture":
        raise SystemExit(fixture(Path(sys.argv[2])))
    if len(sys.argv) == 4 and sys.argv[1] == "--worker":
        raise SystemExit(worker(Path(sys.argv[2]), Path(sys.argv[3])))
    raise SystemExit("Use scripts/benchmark.py --benchmark subdomain")
