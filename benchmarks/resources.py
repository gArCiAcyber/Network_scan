"""Linux resource companion: child CPU accounting and sampled process-tree RSS/fds."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarks.cli import positive_float, write_json
from benchmarks.subdomain import process_identity, stop_worker


def process_tree(pid: int) -> list[int]:
    pending, found = [pid], set()
    while pending:
        current = pending.pop()
        if current in found:
            continue
        found.add(current)
        for task in Path(f"/proc/{current}/task").glob("*/children"):
            try:
                pending.extend(int(child) for child in task.read_text().split())
            except FileNotFoundError:
                pass
    return sorted(found)


def network_counters() -> dict[str, dict[str, int]]:
    interfaces = {}
    for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
        name, values = line.split(":", 1)
        fields = list(map(int, values.split()))
        interfaces[name.strip()] = dict(zip(("rx_bytes", "rx_packets", "tx_bytes", "tx_packets"),
                                            (fields[0], fields[1], fields[8], fields[9])))
    return interfaces


def measure(command: list[str], directory: Path, timeout: float, interval: float = 0.02) -> dict:
    import resource

    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    # Adopt orphaned descendants so an abruptly exited worker cannot leave
    # either live children or zombies behind. This affects only this companion.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "Cannot enable resource companion child reaping")
    network_before = network_counters()
    owned, cleanup_errors = {}, []
    peaks = {"sampled_tree_peak_rss_bytes": 0, "sampled_tree_peak_descriptors": 0,
             "sampled_tree_peak_processes": 0}
    observations, unavailable = 0, []
    started = time.perf_counter()
    process = subprocess.Popen(command, start_new_session=True)
    try:
        while process.poll() is None:
            rss, descriptors, live = 0, 0, 0
            for pid in process_tree(process.pid):
                try:
                    identity = process_identity(pid)
                    if identity is None:
                        continue
                    owned[pid] = {"pid": pid, "process_identity": identity, "group": os.getpgid(pid)}
                    status = Path(f"/proc/{pid}/status").read_text()
                    rss += next((int(line.split()[1]) * 1024 for line in status.splitlines()
                                 if line.startswith("VmRSS:")), 0)
                    descriptors += len(list(Path(f"/proc/{pid}/fd").iterdir()))
                    live += 1
                except (FileNotFoundError, ProcessLookupError):
                    continue
                except PermissionError:
                    unavailable.append(f"Cannot inspect PID {pid}")
            peaks["sampled_tree_peak_rss_bytes"] = max(peaks["sampled_tree_peak_rss_bytes"], rss)
            peaks["sampled_tree_peak_descriptors"] = max(peaks["sampled_tree_peak_descriptors"], descriptors)
            peaks["sampled_tree_peak_processes"] = max(peaks["sampled_tree_peak_processes"], live)
            observations += 1
            if time.perf_counter() - started >= timeout:
                raise TimeoutError("Resource companion deadline exceeded")
            time.sleep(interval)
        exit_code = process.wait()
    finally:
        # A child can outlive a parent that exits between sampling ticks.
        # The subreaper owns these adopted descendants even if no tick saw them.
        for pid in process_tree(os.getpid()):
            if pid == os.getpid():
                continue
            try:
                identity = process_identity(pid)
                if identity is not None:
                    owned[pid] = {"pid": pid, "process_identity": identity, "group": os.getpgid(pid)}
                else:
                    # Reap already-exited adopted children for CPU accounting too.
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass
            except ProcessLookupError:
                pass
        # The existing watchdog handles providers that own separate process groups.
        write_json(directory / "resource-processes.json", list(owned.values()))
        watchdog = directory / "resource-watchdog"
        watchdog.mkdir(exist_ok=True)
        try:
            (watchdog / "launches.jsonl").write_text("".join(json.dumps(row) + "\n" for row in owned.values()
                                                            if row["group"] == row["pid"]), encoding="utf-8")
            stop_worker(process, watchdog)
            for signum in (signal.SIGTERM, signal.SIGKILL):
                for pid, row in owned.items():
                    if process_identity(pid) == row["process_identity"]:
                        try:
                            os.kill(pid, signum)
                        except ProcessLookupError:
                            pass
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    for pid in owned:
                        try:
                            os.waitpid(pid, os.WNOHANG)
                        except ChildProcessError:
                            pass
                    if not any(process_identity(pid) == row["process_identity"] for pid, row in owned.items()):
                        break
                    time.sleep(.02)
            survivors = [pid for pid, row in owned.items() if process_identity(pid) == row["process_identity"]]
            if survivors:
                cleanup_errors.append(f"Observed descendants survived: {survivors}")
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            cleanup_errors.append(str(error))
    elapsed = time.perf_counter() - started
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    network_after = network_counters()
    traffic = {name: {key: row[key] - network_before[name][key] for key in row}
               for name, row in network_after.items() if name in network_before}
    if unavailable or not observations:
        peaks = dict.fromkeys(peaks)
    return {"execution_seconds": elapsed, "exit_code": exit_code,
            "cpu_user_seconds": after.ru_utime - before.ru_utime,
            "cpu_system_seconds": after.ru_stime - before.ru_stime,
            "peak_memory_bytes": after.ru_maxrss * 1024, **peaks,
            "measurement_source": "linux_proc_resource_companion", "sample_interval_seconds": interval,
            "observations": observations, "unavailable": sorted(set(unavailable)),
            "traffic": traffic, "cleanup_errors": cleanup_errors,
            "memory_policy": "ru_maxrss is the largest waited child high-water mark, not a simultaneous tree total; "
                             "sampled RSS sums processes and may count shared pages repeatedly; short children may be missed",
            "traffic_policy": "Interface deltas include all traffic in this namespace during the companion; "
                              "they are workload-only only in a dedicated isolated namespace"}


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--output", required=True, type=Path)
    cli.add_argument("--timeout", type=positive_float, default=110)
    cli.add_argument("command", nargs=argparse.REMAINDER)
    args = cli.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if sys.platform != "linux" or not command:
        cli.error("Requires Linux and a command after --")
    if args.output.exists():
        cli.error("Resource output already exists")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt
    previous = {signum: signal.signal(signum, interrupt) for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        result = measure(command, args.output.parent, args.timeout)
    except KeyboardInterrupt:
        write_json(args.output, {"status": "interrupted"})
        return 130
    except (OSError, RuntimeError, TimeoutError) as error:
        write_json(args.output, {"error": str(error), "status": "failed"})
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    write_json(args.output, result)
    return result["exit_code"] if not result["cleanup_errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
