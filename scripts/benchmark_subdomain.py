"""Hylianlab offline benchmark through isolated real CLI workers."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import platform
import runpy
import signal
import socket
import subprocess
import sys
import time
import traceback
import uuid
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[1]
sys.path.insert(0, str(ROOT))
from scripts.benchmark_subdomain_data import DOMAIN, build_dataset, in_scope

PROVIDER_SCRIPT = SCRIPT.with_name("benchmark_subdomain_provider.py")
FIX_REVISION = "284a07111f90a8714dbc8b8e7fb6e0a3045f8a5e"


def scenarios(profile: str) -> list[dict]:
    def case(name, size=1000, providers=None, mode="completed", **settings):
        return {"name": name, "size": size, "providers": providers or ["subfinder", "amass"],
                "mode": mode, "slow": mode == "timed_out",
                "comparison_eligible": mode == "completed", **settings}

    cases = [case("baseline-1k"), case("subfinder-1k", providers=["subfinder"]),
             case("amass4-1k", providers=["amass"], amass_version="4.2.0"),
             case("amass5-1k", providers=["amass"]),
             case("duplicates-1k", duplicates=10), case("invalid-scope", dirty=True),
             case("gradual-1k", batch_size=50, delay_seconds=.01),
             case("bursts-1k", batch_size=250, delay_seconds=.03),
             case("stream-pressure", duplicates=10, pressure=True), case("empty", size=0),
             case("failure-partial", mode="failed"),
             case("abrupt-partial", mode="failed", amass_version="4.2.0", abrupt=True),
             case("failure-empty", size=0, providers=["subfinder"], mode="failed"),
             case("timeout-partial", mode="timed_out"),
             case("timeout-empty", size=0, providers=["subfinder"], mode="timed_out"),
             case("sigint-subfinder", mode="interrupted", interrupt_provider="subfinder"),
             case("sigint-amass", mode="interrupted", interrupt_provider="amass"),
             case("sigint-save", mode="interrupted", interrupt_save=True),
             case("writer-error", mode="writer_error"),
             case("baseline-10k", size=10_000)]
    if profile == "full":
        cases += [case("baseline-100k", size=100_000),
                  case("duplicates-100k", size=100_000, duplicates=10),
                  case("gradual-100k", size=100_000, batch_size=1000, delay_seconds=.02)]
    return cases


@lru_cache(maxsize=3)
def dataset(size):
    return build_dataset(size)


def fixture_data(case: dict, provider: str) -> dict:
    data = dataset(case["size"] or 1000)
    expected = list(data["providers"][provider]) if case["size"] else []
    status = "completed"
    fault_provider = case.get("interrupt_provider", "amass" if "amass" in case["providers"] else "subfinder")
    if case["mode"] in {"failed", "timed_out", "interrupted"} and not case.get("interrupt_save"):
        if provider == fault_provider:
            expected = expected[:120]
            status = case["mode"]
        elif case["mode"] == "interrupted" and fault_provider == "subfinder":
            expected, status = [], "skipped"
    # A failed second checkpoint must retain the first actual TXT/JSON snapshot.
    if case["mode"] == "writer_error" and provider == "amass":
        saved_expected, saved_status = [], "skipped"
    else:
        saved_expected, saved_status = expected, status
    lines = expected * case.get("duplicates", 1)
    if lines:
        lines += [expected[0].upper() + ".", "\x1b[32m" + expected[-1] + "\x1b[0m"]
    lines += ["", "no-name", "provider status message", "error.laboratory: diagnostic"]
    if case.get("dirty"):
        lines += data["rejected"]
    version = "2.16.0" if provider == "subfinder" else case.get("amass_version", "5.0.0")
    if provider == "amass" and version == "4.2.0":
        lines = [f"{name} (FQDN) --> cname_record --> {name} (FQDN)" if in_scope(name) else name
                 for name in lines]
    return {"domain": DOMAIN, "version": version, "expected": saved_expected, "status": saved_status,
            "accepted_expected": expected, "execution_status": status,
            "exit_code": 9 if case.get("abrupt") and status == "failed" else
                         7 if saved_status == "failed" else 0 if saved_status == "completed" else None,
            "lines": lines, "batch_size": case.get("batch_size", 256),
            "delay_seconds": case.get("delay_seconds", 0.0), "newline": "\r\n",
            "final_newline": status == "interrupted",
            "abrupt": case.get("abrupt", False),
            "stderr": "fixture diagnostic\n" * (8192 if case.get("pressure") else 1)}


def process_identity(pid: int) -> str | None:
    """Identify a process birth before using a retained PID during cleanup."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.GetProcessTimes.argtypes = (wintypes.HANDLE, *([ctypes.POINTER(ctypes.c_ulonglong)] * 4))
        kernel.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            if ctypes.get_last_error() == 87:  # The PID no longer exists.
                return None
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            exit_code = wintypes.DWORD()
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                raise ctypes.WinError(ctypes.get_last_error())
            if exit_code.value != 259:  # STILL_ACTIVE
                return None
            times = [ctypes.c_ulonglong() for _ in range(4)]
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
                raise ctypes.WinError(ctypes.get_last_error())
            return str(times[0].value)
        finally:
            kernel.CloseHandle(handle)
    try:
        record = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    # comm may contain spaces or parentheses; starttime is field 22.
    fields = record.rsplit(")", 1)[1].split()
    return None if fields[0] == "Z" else fields[19]


def stop_worker(process: subprocess.Popen, directory: Path | None = None) -> None:
    if process.poll() is None:
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
    if directory is None or not (directory / "launches.jsonl").exists():
        return
    # Providers create their own POSIX sessions; killing the worker's group alone
    # cannot finish their cleanup. Birth identities prevent killing a reused PID.
    entries = [json.loads(line) for line in (directory / "launches.jsonl").read_text(encoding="utf-8").splitlines()]
    for entry in entries:
        identity = entry.get("process_identity")
        if identity is None or process_identity(entry["pid"]) != identity:
            continue
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(entry["pid"]), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
        else:
            try:
                if os.getpgid(entry["pid"]) != entry["pid"]:
                    raise RuntimeError("Owned provider has an unexpected process group")
                os.killpg(entry["pid"], signal.SIGKILL)
            except ProcessLookupError:
                continue
        deadline = time.monotonic() + 3
        while process_identity(entry["pid"]) == identity:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Owned fixture PID {entry['pid']} survived cleanup")
            time.sleep(.02)


def worker(checkout: Path, manifest: Path) -> int:
    sys.path.insert(0, str(checkout))
    import ssl  # Initialize its socket subclasses before guarding outbound traffic.
    from modules import subdomain, json_exporter
    config = json.loads(manifest.read_text(encoding="utf-8"))
    directory = manifest.parent
    real_popen, real_socket, real_getaddrinfo = subprocess.Popen, socket.socket, socket.getaddrinfo
    real_runner = subdomain.run_passive_provider
    children, calls, signals = [], [], []
    accepted = {name: set() for name in config["providers"]}
    received = dict.fromkeys(config["providers"], 0)
    provider_started, first_candidate = {}, {}
    metrics = {"merge_seconds": 0.0, "txt_write_seconds": 0.0, "json_write_seconds": 0.0,
               "json_build_seconds": 0.0, "peak_memory_bytes": None,
               "memory_reason": "No validated passive process-tree memory collector"}
    signal_requested = False

    def interrupt(signum, _frame):
        signals.append({"signal": signal.Signals(signum).name, "received": True, "pid": os.getpid()})
        raise KeyboardInterrupt

    for signum in (signal.SIGINT, signal.SIGTERM, *([signal.SIGBREAK] if os.name == "nt" else [])):
        signal.signal(signum, interrupt)

    class LocalSocket(real_socket):
        def connect(self, address):
            if not isinstance(address, tuple) or address[:2] != ("127.0.0.1", 4000):
                raise AssertionError(f"Offline benchmark attempted external connection: {address!r}")
            return super().connect(address)

        def connect_ex(self, address):
            if not isinstance(address, tuple) or address[:2] != ("127.0.0.1", 4000):
                raise AssertionError("Offline benchmark attempted external connection")
            return super().connect_ex(address)

    def lookup(host, *args, **kwargs):
        if host != "127.0.0.1":
            raise AssertionError(f"Offline benchmark attempted DNS resolution: {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    executables = {}
    for name in config["providers"]:
        executable = directory / (name + ".py" if os.name == "nt" else name)
        executable.write_text(f"#!{sys.executable}\nimport sys\nfrom pathlib import Path\n"
            f"sys.path.insert(0, {str(ROOT)!r})\nfrom scripts.benchmark_subdomain_provider import main\n"
            f"raise SystemExit(main({name!r}, Path({str(directory / (name + '.json'))!r}), sys.argv[1:]))\n",
            encoding="utf-8")
        executable.chmod(0o755)
        executables[str(executable)] = name
    amass_config = directory / "amass-config.yaml"
    amass_config.write_text("active: false\nbruteforce:\n  enabled: false\nalterations:\n  enabled: false\n", encoding="utf-8")
    for key in list(os.environ):
        if key.startswith(("AMASS_DB_", "AMASS_ENGINE_")):
            del os.environ[key]
    os.environ["AMASS_CONFIG"] = str(amass_config)

    def launch(command, **kwargs):
        if (os.name == "nt" and len(command) == 5 and command[0] == "taskkill"
                and command[1] == "/PID" and command[3:] == ["/T", "/F"]
                and str(command[2]) in {str(child.pid) for child in children}):
            return real_popen(command, **kwargs)
        if str(command[0]) not in executables:
            raise ValueError(f"Unexpected offline process: {command!r}")
        name = executables[str(command[0])]
        arguments = list(map(str, command[1:]))
        if (name == "subfinder" and "-d" in arguments) or (name == "amass" and arguments[0] == "enum"):
            provider_started[name] = time.perf_counter()
        actual = [sys.executable, "-u", *map(str, command)] if os.name == "nt" else list(map(str, command))
        process = real_popen(actual, **kwargs)
        children.append(process)
        with (directory / "launches.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"provider": name, "pid": process.pid, "process_identity": process_identity(process.pid),
                                  "requested": list(map(str, command)), "executed": actual}) + "\n")
        return process

    def observe(*args, **kwargs):
        nonlocal signal_requested
        bound = inspect.signature(real_runner).bind(*args, **kwargs).arguments
        name = str(bound["provider_name"]).lower().split()[0]
        is_data = bound["domain"] == DOMAIN
        if is_data:
            original_callback = kwargs.get("candidate_callback")
            original_parser = kwargs.get("output_parser")

            def candidate(host):
                nonlocal signal_requested
                if original_callback is not None:
                    original_callback(host)
                accepted[name].add(host)
                first_candidate.setdefault(name, time.perf_counter() - provider_started[name])
                if (config.get("interrupt_provider") == name and not signal_requested
                        and len(accepted[name]) == config["interrupt_after"]):
                    # Confirm the emitter finished its fixed prefix and retained logs.
                    stage = "discovery" if name == "subfinder" else "subs" if "subs" in bound["command"] else "enum"
                    deadline = time.monotonic() + 5
                    while not list(directory.glob(f"{name}-{stage}-*.ready.json")):
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Interrupted provider did not acknowledge its fixed prefix")
                        time.sleep(.01)
                    signal_requested = True
                    signals.append({"signal": "SIGINT", "requested": True, "accepted": len(accepted[name])})
                    signal.raise_signal(signal.SIGINT)

            def parse(line):
                received[name] += 1
                return original_parser(line) if original_parser is not None else line

            kwargs["candidate_callback"], kwargs["output_parser"] = candidate, parse
        started = time.perf_counter()
        try:
            result = real_runner(*args, **kwargs)
        except subdomain.ProviderInterrupted as error:
            result = error.result
            raise
        finally:
            if "result" in locals():
                checkpoint = {"provider_name": bound["provider_name"], "command": list(map(str, bound["command"])),
                              "elapsed_seconds": time.perf_counter() - started, "result": asdict(result)}
                calls.append(checkpoint)
                (directory / "runner-results.json").write_text(json.dumps(calls), encoding="utf-8")
        return result

    namespace = runpy.run_path(str(checkout / "hylianscan.py"), run_name="hylianlab_worker")["main"].__globals__
    txt_calls = 0

    def timed(function, metric, txt=False):
        def call(*args, **kwargs):
            nonlocal txt_calls, signal_requested
            if txt:
                txt_calls += 1
                if txt_calls == 2 and config.get("writer_error"):
                    raise OSError("Injected laboratory TXT writer failure")
                if txt_calls == 2 and config.get("interrupt_save") and not signal_requested:
                    signal_requested = True
                    signals.append({"signal": "SIGINT", "requested": True, "stage": "before_txt_write"})
                    signal.raise_signal(signal.SIGINT)
            started = time.perf_counter()
            try:
                return function(*args, **kwargs)
            finally:
                metrics[metric] += time.perf_counter() - started
        return call

    sys.argv = [str(checkout / "hylianscan.py"), DOMAIN, "--quiet", "--output", "evidence/subdomains.txt",
                "--json-output", "passive.json"]
    for executable, name in executables.items():
        sys.argv += ["--" + name, "--" + name + "-path", executable,
                     "--" + name + "-timeout", str(config["provider_timeout"])]
    exit_code = 0
    try:
        with (patch.object(subprocess, "Popen", side_effect=launch),
              patch.object(subdomain, "run_passive_provider", side_effect=observe),
              patch.object(socket, "socket", LocalSocket), patch.object(socket, "getaddrinfo", side_effect=lookup),
              patch.dict(namespace, {
                  "merge_subdomain_results": timed(namespace["merge_subdomain_results"], "merge_seconds"),
                  "save_subdomain_results": timed(namespace["save_subdomain_results"], "txt_write_seconds", txt=True),
                  "write_subdomain_json_report": timed(namespace["write_subdomain_json_report"], "json_write_seconds")}),
              patch.object(json_exporter, "build_subdomain_discovery_document",
                           side_effect=timed(json_exporter.build_subdomain_discovery_document, "json_build_seconds"))):
            namespace["main"]()
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
        cleanup_errors = []
        for child in children:
            try:
                if child.poll() is None:
                    subdomain.stop_provider(child)
                child.wait(timeout=3)
            except (OSError, subprocess.SubprocessError) as error:
                cleanup_errors.append(str(error))
        metrics["first_candidate_seconds"] = {name: first_candidate.get(name) for name in config["providers"]}
        metrics["received_lines"] = received
        metrics["accepted_unique"] = {name: len(values) for name, values in accepted.items()}
        (directory / "worker.json").write_text(json.dumps({"exit_code": exit_code, "metrics": metrics,
            "signals": signals, "cli_command": sys.argv,
            "provider_processes_reaped": all(child.poll() is not None for child in children),
            "cleanup_errors": cleanup_errors, "network_policy": "Only loopback Amass readiness connections",
            "launcher_adapter": "python executable adapter" if os.name == "nt" else "native executable paths"}), encoding="utf-8")
    return exit_code


def validate_document(document: dict, text: str, expected: dict) -> tuple[list[str], dict]:
    errors = []

    def check_names(label, observed, wanted):
        if not isinstance(observed, list) or any(not isinstance(name, str) for name in observed):
            errors.append(f"{label}: expected a list of names")
            return set()
        actual = set(observed)
        if actual != wanted:
            errors.append(f"{label}: missing {len(wanted - actual)}, unexpected {len(actual - wanted)}; "
                          f"examples={sorted(wanted ^ actual)[:8]}")
        if observed != sorted(actual):
            errors.append(f"{label}: duplicate or unsorted names")
        return actual

    wanted_sources = {}
    providers = document.get("providers", [])
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
        statuses[name] = {key: result.get(key) for key in ("status", "exit_code", "reason", "compatibility")}
        if result.get("count") != len(observed) or result.get("role") != "discovery":
            errors.append(f"{name}: incorrect count or provider role")
        if result.get("status") != data["status"] or result.get("exit_code") != data["exit_code"]:
            errors.append(f"{name}: incorrect completion status or exit code")
        if data["status"] != "completed" and not result.get("reason"):
            errors.append(f"{name}: partial/skipped results lack a reason")
        if data["status"] == "completed" and result.get("reason") is not None:
            errors.append(f"{name}: completed provider has an unexpected error reason")
        if result.get("compatibility", {}).get("version") != data["version"]:
            errors.append(f"{name}: provider version contract was not verified")
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
    provider_timeout = min(args.provider_timeout, 3.0) if case["mode"] == "timed_out" else args.provider_timeout
    manifest = {"domain": DOMAIN, "providers": case["providers"], "provider_timeout": provider_timeout,
                "interrupt_provider": case.get("interrupt_provider"),
                "interrupt_after": len(expected.get(case.get("interrupt_provider"), {}).get("accepted_expected", [])),
                "interrupt_save": case.get("interrupt_save", False), "writer_error": case["mode"] == "writer_error"}
    common.write_json(directory / "fixture.json", manifest)
    common.write_json(directory / "dataset.json", dataset(case["size"] or 1000))
    for name, data in expected.items():
        emission = {**data, "status": data["execution_status"]}
        common.write_json(directory / f"{name}.json", emission)
    common.write_json(directory / "expected.json", expected)
    workload_hash = hashlib.sha256(json.dumps({"manifest": manifest, "data": expected}, sort_keys=True).encode()).hexdigest()
    command = [args.python, str(SCRIPT), "--worker", str(checkout), str(directory / "fixture.json")]
    wanted_exit = 130 if case["mode"] == "interrupted" else 1 if case["mode"] in {"failed", "timed_out", "writer_error"} else 0
    sample = {"id": directory.name, "directory": str(directory), "scenario": case["name"], "variant": variant,
              "role": role, "index": index, "command": command, "cwd": str(directory),
              "workload_sha256": workload_hash, "status": "running", "validation_errors": [],
              "cleanup_errors": [], "providers": {}, "metrics": {}, "comparison_eligible": case["comparison_eligible"],
              "expected_exit_code": wanted_exit, "expected_outcome": case["mode"]}
    report["samples"].append(sample)
    common.write_json(directory / "sample.json", sample)
    common.save_report(report, time.perf_counter() - report["_started"], args.regression_percent)
    process, caught = None, None
    print(f"[{role}] {case['name']}: {variant}, sample {index}", flush=True)
    try:
        with (directory / "worker.log").open("w", encoding="utf-8") as log:
            group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
            execution_started = time.perf_counter()
            process = subprocess.Popen(command, cwd=directory, stdout=log, stderr=log, **group)
            sample["exit_code"] = process.wait(timeout=args.run_timeout)
            sample["observed_exit_code"] = sample["exit_code"]
        sample["metrics"] = {"execution_seconds": time.perf_counter() - execution_started,
                             "measurement_source": "stdlib_perf_counter"}
        if sample["exit_code"] != wanted_exit:
            sample["validation_errors"].append(f"CLI exit {sample['exit_code']}, expected {wanted_exit}")
        document = json.loads((directory / "output/passive.json").read_text(encoding="utf-8"))
        text = (directory / "evidence/subdomains.txt").read_text(encoding="utf-8")
        errors, observations = validate_document(document, text, expected)
        sample["validation_errors"].extend(errors)
        sample["providers"] = observations["providers"]
        sample["metrics"].update(observations["metrics"])
        worker_record = json.loads((directory / "worker.json").read_text(encoding="utf-8"))
        sample["worker"] = worker_record
        sample["cli_command"] = worker_record["cli_command"]
        sample["metrics"].update(worker_record["metrics"])
        if not worker_record["provider_processes_reaped"]:
            sample["cleanup_errors"].append("Fixture processes were not reaped")
        sample["cleanup_errors"].extend(worker_record["cleanup_errors"])
        ledger = [json.loads(line) for line in (directory / "provider-commands.jsonl").read_text(encoding="utf-8").splitlines()]
        sample["provider_commands"] = ledger
        starts = [entry["provider"] for entry in ledger if entry["stage"] in {"discovery", "enum"}]
        wanted_starts = [name for name, data in expected.items() if data["execution_status"] != "skipped"]
        if starts != wanted_starts:
            sample["validation_errors"].append("Provider launch order differs from the fixture")
        if any(entry["arguments"] == ["enum", "-h"] and expected[entry["provider"]]["version"] == "5.0.0" for entry in ledger):
            sample["validation_errors"].append("Unsafe Amass 5 help contract")
        journals = list((directory / "evidence").glob("subdomains_observed_*.tsv"))
        journal_names = {name: set() for name in case["providers"]}
        for path in journals:
            for line in path.read_text(encoding="utf-8").splitlines():
                name, host = line.split("\t", 1)
                journal_names[name].add(host)
        for name, data in expected.items():
            if journal_names[name] != set(data["accepted_expected"]):
                sample["validation_errors"].append(f"{name}: actual accepted-name journal differs from the oracle")
        sample["metrics"]["saved_unique"] = len(document["results"]["subdomains"])
        sample["metrics"]["emitted_records"] = {
            entry["provider"]: json.loads(Path(entry["stdout"]).with_suffix("").with_suffix(".ready.json").read_text())["emitted_count"]
            for entry in ledger if entry["stage"] in {"discovery", "subs"}
            and Path(entry["stdout"]).with_suffix("").with_suffix(".ready.json").exists()}
        sample["metrics"]["emitted_stdout_bytes"] = sum(Path(entry["stdout"]).stat().st_size for entry in ledger if entry["data_stage"])
        sample["metrics"]["emitted_stderr_bytes"] = sum(Path(entry["stderr"]).stat().st_size for entry in ledger if entry["data_stage"])
        if case["mode"] == "interrupted" and not any(s.get("received") and s["signal"] == "SIGINT" for s in worker_record["signals"]):
            sample["validation_errors"].append("Expected actual SIGINT was not received")
        sample["status"] = "failed" if sample["validation_errors"] or sample["cleanup_errors"] else "completed"
    except KeyboardInterrupt as error:
        sample["status"], caught = "interrupted", error
    except Exception as error:
        sample["status"] = "failed"
        sample["error"] = f"{type(error).__name__}: {error}"
    finally:
        previous = {s: signal.signal(s, signal.SIG_IGN) for s in (signal.SIGINT, signal.SIGTERM)}
        try:
            if process is not None:
                try:
                    stop_worker(process, directory)
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
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
    if args.subdomain_scenarios:
        unknown = set(args.subdomain_scenarios) - {case["name"] for case in cases}
        if unknown:
            raise ValueError(f"Unknown scenario for {args.profile}: {', '.join(sorted(unknown))}")
        cases = [case for case in cases if case["name"] in args.subdomain_scenarios]
    timestamp = common.build_timestamp() + "_" + uuid.uuid4().hex[:8]
    directory = (args.output_dir.resolve() / timestamp if args.output_dir else
                 common.resolve_output_workspace("benchmark", timestamp=timestamp))
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": {"name": "hylianscan_benchmark", "version": 1}, "benchmark": "subdomain",
              "mode": "offline", "profile": args.profile, "directory": str(directory), "started_utc": timestamp,
              "status": "running", "options": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
              "versions": {}, "scenarios": cases, "samples": [],
              "validation": {"battery_completed": False, "correctness_passed": None},
              "domain": DOMAIN, "reused_passive_fix_revision": FIX_REVISION,
              "scope_policy": "ASCII DNS hostnames in hylianlab.test, including the apex; wildcards and URLs rejected",
              "timing_policy": "Worker launch through exit, including bootstrap, fixture subprocesses, evidence logging, CLI and reports; fixture preparation and validation excluded",
              "limitations": ["Fixtures do not verify real provider compatibility or discovery coverage",
                              "No live discovery, DNSx, HTTPx, CPU or validated memory measurements"],
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
            "external_providers": "Not used; local executable fixtures emulate version/help and collection contracts",
            "kali_lab_executed": sys.platform.startswith("linux") and Path("/etc/os-release").exists()
                and "ID=kali" in Path("/etc/os-release").read_text(),
            "provider_contracts": {"subfinder": "2.16.0 simulated", "amass": "5.0.0/4.2.0 simulated"}}
        report["harness_sha256"] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in (SCRIPT, ROOT / "scripts/benchmark.py", PROVIDER_SCRIPT,
                                                 SCRIPT.with_name("benchmark_subdomain_data.py"))}
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
    if len(sys.argv) == 4 and sys.argv[1] == "--worker":
        raise SystemExit(worker(Path(sys.argv[2]), Path(sys.argv[3])))
    raise SystemExit("Use scripts/benchmark.py --benchmark subdomain")
