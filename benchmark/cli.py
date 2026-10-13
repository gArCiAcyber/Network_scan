#!/usr/bin/env python3
"""Benchmark Hylianscan TCP scans in a Linux lab or passive discovery offline."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import re
import shlex
import shutil
import signal
import ssl
import statistics
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.output import build_timestamp, resolve_output_workspace
from benchmark.services import banner
from tests.fixtures.certificates import TEST_CERTIFICATE_PEM


TARGET = "192.0.2.2"
SCANNER = "192.0.2.1"
CERTIFICATE_SHA256 = hashlib.sha256(
    ssl.PEM_cert_to_DER_cert(TEST_CERTIFICATE_PEM)
).hexdigest()


@dataclass
class Scenario:
    name: str
    ports: list[int]
    services: list[dict]
    filtered_ports: list[int]
    slow: bool = False

    def config(self, args: argparse.Namespace) -> dict:
        occupied = {service["port"] for service in self.services} | set(self.filtered_ports)
        return {
            "address": TARGET,
            "services": self.services,
            "filtered_ports": self.filtered_ports,
            "closed_check_port": next(port for port in self.ports if port not in occupied),
            "workers": args.workers,
            "timeout": args.timeout,
            "delay_ms": args.delay_ms,
        }


def select_ports(count: int, required: list[int]) -> list[int]:
    """Keep exact, deterministic sizes while including every expected service."""
    ports = set(required)
    if len(ports) >= count:
        raise ValueError("Port count must leave room for at least one closed port.")
    if count == 65535:
        return list(range(1, 65536))
    for port in list(range(20000, 65536)) + list(range(1, 20000)):
        ports.add(port)
        if len(ports) == count:
            return sorted(ports)
    raise ValueError("Invalid port count.")


def scenarios(args: argparse.Namespace) -> list[Scenario]:
    def make(name: str, count: int, services: list[dict], filtered: list[int] | None = None,
             slow: bool = False) -> Scenario:
        filtered = filtered or []
        return Scenario(name, select_ports(count, [s["port"] for s in services] + filtered),
                        services, filtered, slow)

    plain = [{"port": 2222, "kind": "banner"}]
    protocols = plain + [{"port": 8080, "kind": "http"}, {"port": 8443, "kind": "https"}]
    cases = [
        make("sparse", args.base_ports, plain),
        make("protocols", args.base_ports, protocols),
        make("silent", args.base_ports, [{"port": 9000 + index, "kind": "silent"}
                                        for index in range(args.silent_listeners)], slow=True),
        make("mixed", args.base_ports, plain, list(range(19000, 19000 + args.drop_ports)), slow=True),
        make("scaling-sparse", args.scale_ports, plain),
        make("scaling-open", args.scale_ports,
             [{"port": 10000 + index, "kind": "banner"} for index in range(args.many_open)]),
    ]
    if args.profile == "full":
        full_services = plain + [{"port": 10000 + index, "kind": "banner"}
                                 for index in range(args.full_open - 1)]
        cases.append(make("scaling-all", 65535, full_services))
    if args.tcp_scenarios:
        unknown = set(args.tcp_scenarios) - {case.name for case in cases}
        if unknown:
            raise ValueError("Unknown TCP scenario: " + ", ".join(sorted(unknown)))
        cases = [case for case in cases if case.name in args.tcp_scenarios]
    return cases


def port_expression(ports: list[int]) -> str:
    """Compress ranges so 65,535 ports stay well below exec argument limits."""
    groups = []
    start = end = ports[0]
    for port in ports[1:]:
        if port == end + 1:
            end = port
        else:
            groups.append(str(start) if start == end else f"{start}-{end}")
            start = end = port
    groups.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(groups)


def write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def run(command: list[str], *, cwd: Path | None = None, timeout: float = 30,
        check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                            timeout=timeout, check=False)
    if check and result.returncode:
        raise RuntimeError(f"{shlex.join(command)} exited {result.returncode}: "
                           f"{(result.stderr or result.stdout)[-2000:]}")
    return result


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Must be greater than zero.")
    return number


def positive_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("Must be a finite number greater than zero.")
    return number


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--benchmark", choices=BENCHMARKS, default="tcp_scan",
                     help="Select the benchmark type (default: tcp_scan).")
    cli.add_argument("--profile", choices=("quick", "full"), default="quick",
                     help="Select workloads and repetitions; both validate correctness (default: quick).")
    cli.add_argument("--candidate", type=Path, default=ROOT, help="Candidate source checkout.")
    cli.add_argument("--reference", type=Path, help="Optional reference source checkout.")
    cli.add_argument("--python", default=sys.executable, help="Same interpreter for both versions.")
    cli.add_argument("--output-dir", type=Path, help="Parent directory for a new unique battery.")
    cli.add_argument("--base-ports", type=positive_int, default=400)
    cli.add_argument("--scale-ports", type=positive_int, default=4096)
    cli.add_argument("--many-open", type=positive_int, help="Dense scaling listeners (quick: 64; full: 256).")
    cli.add_argument("--workers", type=positive_int, default=50)
    cli.add_argument("--timeout", type=positive_float, default=1.0)
    cli.add_argument("--max-rate", type=positive_float, help="Connection-start cap, not a packet rate.")
    cli.add_argument("--delay-ms", type=float, default=0, help="Fixed one-way netem delay on both links.")
    cli.add_argument("--warmups", type=int, help="Warm-ups per scenario/version (quick: 1; full: 2).")
    cli.add_argument("--fast-runs", type=positive_int, help="Override pilot-selected fast repetitions.")
    cli.add_argument("--slow-runs", type=positive_int, help="Override pilot-selected long repetitions.")
    cli.add_argument("--full-runs", type=positive_int, default=5, help="Full-port repetitions.")
    cli.add_argument("--budget-seconds", type=positive_float, default=180,
                     help="Quick battery target; a pilot preserves all cases and estimates feasibility.")
    cli.add_argument("--run-timeout", type=positive_float, default=120,
                     help="Safety deadline per measured or companion execution.")
    cli.add_argument("--regression-percent", type=positive_float,
                     help="Opt-in median execution-time threshold after reference/reference calibration.")
    cli.add_argument("--vm-notes", default="", help="Guest-invisible host/VM configuration.")
    cli.add_argument("--provider-timeout", type=positive_float, default=30.0,
                     help="Offline subdomain provider budget in seconds (default: 30).")
    cli.add_argument("--scenario", action="append", dest="subdomain_scenarios",
                     help="Select an offline subdomain scenario; repeat to select several.")
    cli.add_argument("--tcp-scenario", action="append", dest="tcp_scenarios",
                     help="Select a TCP scenario; repeat to select several.")
    cli.add_argument("--first-variant", choices=("reference", "candidate"), default="reference",
                     help="First variant in alternating measured pairs (default: reference).")
    cli.add_argument("--min-free-gib", type=positive_float, default=1.0,
                     help="Minimum available evidence-disk space before each sample (default: 1 GiB).")
    cli.add_argument("--drop-ports", type=positive_int, default=4,
                     help="Number of mixed-case DROP ports, at most 256 (default: 4).")
    cli.add_argument("--silent-listeners", type=positive_int, default=1,
                     help="Silent-case open listeners, at most 256 (default: 1).")
    cli.add_argument("--full-open", type=positive_int, default=1,
                     help="Full-port case open listeners, at most 1024 (default: 1).")
    cli.add_argument("--resources", action="store_true",
                     help="Run separate Linux process-tree resource samples; excluded from primary timings.")
    cli.add_argument("--passive-observations", choices=("detailed", "minimal"), default="detailed",
                     help="Passive worker observation; saved-evidence oracles remain enabled.")
    cli.add_argument("--reference-observations", choices=("detailed", "minimal"),
                     help="Compare observation modes on identical passive product snapshots.")
    cli.add_argument("--diagnostic-profile", action="store_true",
                     help="Profile resource companions only; primary samples stay unprofiled.")
    cli.add_argument("--subfinder-path", default="subfinder", help="Real-provider lab Subfinder executable.")
    cli.add_argument("--amass-path", default="amass", help="Real-provider lab Amass executable.")
    cli.add_argument("--dnsx-path", default="dnsx", help="Real DNSx lab executable.")
    return cli


def resolve_options(args: argparse.Namespace) -> argparse.Namespace:
    if args.benchmark != "subdomain" and args.subdomain_scenarios:
        raise ValueError("--scenario requires --benchmark subdomain.")
    if args.benchmark != "tcp_scan" and args.tcp_scenarios:
        raise ValueError("--tcp-scenario requires --benchmark tcp_scan.")
    args.many_open = args.many_open if args.many_open is not None else (64 if args.profile == "quick" else 256)
    args.warmups = args.warmups if args.warmups is not None else (1 if args.profile == "quick" else 2)
    if not math.isfinite(args.delay_ms) or args.delay_ms < 0 or args.warmups < 0:
        raise ValueError("Delay and warm-up count must be non-negative and finite.")
    if args.benchmark == "tcp_scan" and (not 5 <= args.base_ports <= 65535 or not 5 <= args.scale_ports <= 65535):
        raise ValueError("Port counts must be between 5 and 65535.")
    if args.benchmark == "tcp_scan" and (args.many_open >= args.scale_ports or args.many_open > 1024):
        raise ValueError("Dense listeners must be below the scaling size and at most 1024.")
    if args.benchmark == "tcp_scan" and (args.drop_ports > 256 or args.drop_ports + 1 >= args.base_ports):
        raise ValueError("DROP ports must be at most 256 and leave an open and a closed base port.")
    if args.benchmark == "tcp_scan" and (args.silent_listeners > 256 or args.silent_listeners >= args.base_ports
                                          or args.full_open > 1024):
        raise ValueError("Silent listeners must be below the base size and at most 256; full-port listeners at most 1024.")
    if args.resources and sys.platform != "linux":
        raise ValueError("Process-tree resource samples require Linux /proc and resource accounting.")
    if (args.passive_observations != "detailed" or args.reference_observations) and args.benchmark != "subdomain":
        raise ValueError("Observation modes require --benchmark subdomain.")
    if args.reference_observations and args.reference is None:
        raise ValueError("--reference-observations requires --reference.")
    if args.diagnostic_profile and (not args.resources or args.benchmark not in {"subdomain", "tcp_scan"}):
        raise ValueError("--diagnostic-profile requires --resources and a passive or TCP benchmark.")
    for count in (args.fast_runs, args.slow_runs, args.full_runs):
        if count is not None and count < 2:
            raise ValueError("Measured repetition counts must be at least two.")
    if args.regression_percent is not None and args.reference is None:
        raise ValueError("A regression threshold requires --reference.")
    executable = shutil.which(args.python)
    if executable is None:
        raise ValueError(f"Python executable was not found: {args.python}")
    # Keep virtualenv symlinks: resolving the interpreter could change its environment.
    args.python = str(Path(executable).absolute())
    args.candidate = args.candidate.resolve()
    args.reference = args.reference.resolve() if args.reference else None
    for checkout in (args.candidate, args.reference):
        if checkout is not None and not (checkout / "hylianscan.py").is_file():
            raise ValueError(f"Not a Hylianscan source checkout: {checkout}")
    return args


def parse_counters(document: dict) -> dict[int, int]:
    result = {}
    for item in document["nftables"]:
        counter = item.get("counter", {})
        name = counter.get("name", "")
        if counter.get("table") == "hbench" and name.startswith("p") and name[1:].isdigit():
            result[int(name[1:])] = counter["packets"]
    return result


def validate_document(document: dict, case: Scenario, counters: dict[int, int]) -> list[str]:
    errors = []
    if document.get("schema", {}).get("name") != "hylianscan_tcp_scan":
        errors.append("Unexpected Hylianscan JSON schema.")
    scan = document["scan"]
    if scan["target"]["resolved_ip"] != TARGET or scan["target"]["address_family"] != "ipv4":
        errors.append("Unexpected target address or address family.")
    if scan["scope"]["ports_tested"] != len(case.ports):
        errors.append("Reported scan scope differs from the configured port list.")
    findings = document["results"]["open_ports"]
    actual = {}
    for finding in findings:
        port = finding["port"]
        if type(port) is not int:
            errors.append("An open-port number is not an integer.")
            continue
        if port in actual:
            errors.append(f"Duplicate open port: {port}.")
        actual.setdefault(port, finding)
        if finding.get("address") != TARGET or finding.get("address_family") != "ipv4":
            errors.append(f"Unexpected finding address on port {port}.")
        if finding.get("status") != "open" or finding.get("transport") != "tcp":
            errors.append(f"Unexpected finding state on port {port}.")
    expected = {service["port"]: service["kind"] for service in case.services}
    for port in sorted(set(expected) - set(actual)):
        errors.append(f"Missing open port: {port}.")
    for port in sorted(set(actual) - set(expected)):
        errors.append(f"Unexpected open port: {port}.")
    for port in set(expected) & set(actual):
        kind, finding = expected[port], actual[port]
        raw = finding["banner"]["raw"]
        if kind == "banner" and raw != banner(port):
            errors.append(f"Incorrect banner on port {port}.")
        if kind == "silent" and raw is not None:
            errors.append(f"Silent service unexpectedly supplied evidence on port {port}.")
        if kind in ("http", "https"):
            http, probe = finding["http"], finding["probe"]
            if (not isinstance(raw, str) or "HTTP/1.1 200 OK" not in raw
                    or http["status_code"] != 200 or http["server"] != "hylianscan-mock"
                    or probe["name"] != kind or probe["method"] != "http_head"):
                errors.append(f"Incorrect HTTP/probe evidence on port {port}.")
        if kind == "https":
            tls = finding["tls"]
            if (tls["status"] != "collected" or not tls["handshake"].get("protocol")
                    or tls["certificate"]["fingerprints"]["sha256"] != CERTIFICATE_SHA256
                    or tls["trust"].get("verified") is not False):
                errors.append(f"Incorrect TLS evidence on port {port}.")
    if scan["summary"]["open_ports"] != len(findings):
        errors.append("Summary open-port count differs from the findings.")
    if document["results"]["ipv4"] != findings or document["results"]["ipv6"]:
        errors.append("Address-family result views are inconsistent.")
    for port in case.filtered_ports:
        if counters.get(port, 0) <= 0:
            errors.append(f"No measured DROP traffic on filtered port {port}.")
    return errors


def validate_text(text: str, case: Scenario) -> list[str]:
    """Check saved quiet TXT against the independent service configuration."""
    errors = []
    if "\x1b" in text or "\x9b" in text:
        errors.append("ANSI escapes in saved TCP TXT.")
    actual = {}
    for line in text.splitlines():
        if not re.match(r"- [0-9]", line):
            continue
        match = re.fullmatch(r"- ([0-9]+)/tcp open (\S+) (.+)", line)
        if match is None:
            errors.append("Malformed TCP TXT finding: " + line)
            continue
        port, service, evidence = int(match[1]), match[2], match[3]
        if port in actual:
            errors.append(f"Duplicate TXT open port: {port}.")
        actual[port] = (service, evidence)
    expected = {service["port"]: service["kind"] for service in case.services}
    if set(actual) != set(expected):
        errors.append(f"TXT open ports differ: missing={sorted(set(expected) - set(actual))}, "
                      f"unexpected={sorted(set(actual) - set(expected))}.")
    for port in set(expected) & set(actual):
        wanted = (banner(port) if expected[port] == "banner" else
                  "active, no banner" if expected[port] == "silent" else "200 OK")
        if actual[port][1] != wanted or (expected[port] in ("http", "https") and actual[port][0] != expected[port]):
            errors.append(f"Incorrect TXT banner/evidence on port {port}.")
    if f"Target: {TARGET}" not in text.splitlines() or f"Resolved IP: {TARGET}" not in text.splitlines():
        errors.append("Unexpected TCP TXT target.")
    return errors


def disk_preflight(directory: Path, args: argparse.Namespace) -> dict:
    """Keep an explicit reserve; never remove previous evidence to make room."""
    usage = shutil.disk_usage(directory)
    minimum = int(args.min_free_gib * 1024 ** 3)
    if usage.free < minimum:
        raise RuntimeError(f"Evidence disk has {usage.free} bytes free; {minimum} bytes required. "
                           "Choose a filesystem with more space or a smaller bounded campaign.")
    return {"total_bytes": usage.total, "free_bytes": usage.free, "minimum_free_bytes": minimum}


class Lab:
    """Own only the namespaces, veth pair, config files, and children created here."""

    def __init__(self, directory: Path, config: dict, python: str):
        self.directory, self.config, self.python = directory, config, python
        token = uuid.uuid4().hex[:10]
        self.scanner, self.target = f"hb-{token}-s", f"hb-{token}-t"
        self.links = [f"hb{token}a", f"hb{token}b"]
        self.namespaces: list[str] = []
        self.config_dirs: list[Path] = []
        self.link_created = False
        self.commands: list[list[str]] = []
        self.service_process: subprocess.Popen | None = None
        self.service_log = None

    def root(self, command: list[str], *, check: bool = True, timeout: float = 30):
        self.commands.append(command)
        return run(["sudo", "-n", *command], cwd=self.directory, check=check, timeout=timeout)

    def user_command(self, namespace: str, command: list[str]) -> list[str]:
        return ["sudo", "-n", "ip", "netns", "exec", namespace, "setpriv",
                f"--reuid={os.getuid()}", f"--regid={os.getgid()}", "--init-groups",
                "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all",
                "--no-new-privs", "--", "env", "LC_ALL=C", *command]

    def prepare(self) -> None:
        run(["sudo", "-n", "-v"])
        existing = {line.split()[0] for line in self.root(["ip", "netns", "list"]).stdout.splitlines()}
        existing_links = {item["ifname"] for item in json.loads(self.root(["ip", "-j", "link", "show"]).stdout)}
        if existing & {self.scanner, self.target} or existing_links & set(self.links):
            raise RuntimeError("Laboratory resource name collision; nothing was reused.")
        for name in (self.scanner, self.target):
            # Register the intention before a command that may be interrupted after creation.
            self.namespaces.append(name)
            self.root(["ip", "netns", "add", name])
        self.link_created = True
        self.root(["ip", "link", "add", self.links[0], "type", "veth", "peer", "name", self.links[1]])
        for name, link, address in zip((self.scanner, self.target), self.links, (SCANNER, TARGET)):
            self.root(["ip", "link", "set", link, "netns", name])
            self.root(["ip", "-n", name, "address", "add", address + "/30", "dev", link])
            self.root(["ip", "-n", name, "link", "set", "lo", "up"])
            self.root(["ip", "-n", name, "link", "set", link, "up"])
            if self.config["delay_ms"]:
                self.root(["ip", "netns", "exec", name, "tc", "qdisc", "add", "dev", link,
                           "root", "netem", "delay", f"{self.config['delay_ms']:g}ms"])
        # Numeric targets still trigger PTR lookup in the real CLI. Resolve it locally.
        hosts = self.directory / "hosts"
        hosts.write_text(f"127.0.0.1 localhost\n{TARGET} hylianscan-bench.invalid\n", encoding="ascii")
        resolver = self.directory / "resolv.conf"
        resolver.write_text("nameserver 127.0.0.1\noptions attempts:1 timeout:1\n", encoding="ascii")
        config_dir = Path("/etc/netns") / self.scanner
        if config_dir.exists():
            raise RuntimeError("Namespace config directory already exists; refusing to reuse it.")
        self.config_dirs.append(config_dir)
        self.root(["install", "-d", "-m", "755", str(config_dir)])
        for source in (hosts, resolver):
            self.root(["install", "-m", "644", str(source), str(config_dir / source.name)])
        if self.config["filtered_ports"]:
            self.root(["ip", "netns", "exec", self.target, "nft", "add", "table", "inet", "hbench"])
            self.root(["ip", "netns", "exec", self.target, "nft", "add", "chain", "inet", "hbench", "input",
                       "{ type filter hook input priority 0; policy accept; }"])
            for port in self.config["filtered_ports"]:
                prefix = ["ip", "netns", "exec", self.target, "nft"]
                self.root(prefix + ["add", "counter", "inet", "hbench", f"p{port}"])
                self.root(prefix + ["add", "rule", "inet", "hbench", "input", "tcp", "dport",
                                    str(port), "counter", "name", f"p{port}", "drop"])
        config_path = self.directory / "lab.json"
        write_json(config_path, self.config)
        self.service_log = (self.directory / "services.log").open("w", encoding="utf-8")
        self.service_process = subprocess.Popen(
            self.user_command(self.target, [self.python, str(ROOT / "benchmark/services.py"), str(config_path)]),
            cwd=self.directory, stdout=self.service_log, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 15
        while not (self.directory / "ready.json").exists():
            if self.service_process.poll() is not None:
                raise RuntimeError("Laboratory services exited before readiness; see services.log.")
            if time.monotonic() >= deadline:
                raise TimeoutError("Laboratory listeners were not ready within 15 seconds.")
            time.sleep(0.05)
        readiness = run(self.user_command(self.scanner, [self.python,
                        str(ROOT / "benchmark/services.py"), str(config_path), "--check"]),
                        cwd=self.directory, timeout=max(30, self.config["timeout"] * 4 + self.config["delay_ms"] / 100))
        write_json(self.directory / "readiness.json", json.loads(readiness.stdout))
        self.reset_counters()

    def counters(self) -> dict[int, int]:
        if not self.config["filtered_ports"]:
            return {}
        result = self.root(["ip", "netns", "exec", self.target, "nft", "-j", "list", "counters",
                            "table", "inet", "hbench"])
        return parse_counters(json.loads(result.stdout))

    def reset_counters(self) -> None:
        if self.config["filtered_ports"]:
            self.root(["ip", "netns", "exec", self.target, "nft", "reset", "counters", "table", "inet", "hbench"])
            counters = self.counters()
            if set(counters) != set(self.config["filtered_ports"]) or any(counters.values()):
                raise RuntimeError("Per-port DROP counters were not zero after preparation.")
            write_json(self.directory / "drop-before.json", counters)

    def close(self) -> list[str]:
        """Attempt every cleanup step even if a previous one fails."""
        errors = []
        try:
            (self.directory / "stop").touch()
        except OSError as error:
            errors.append(str(error))
        for name in self.namespaces:
            try:
                result = self.root(["ip", "netns", "pids", name], check=False)
                pids = [str(int(value)) for value in result.stdout.split()]
                if pids:
                    self.root(["kill", "-TERM", "--", *pids], check=False)
                deadline = time.monotonic() + 3
                while pids and time.monotonic() < deadline:
                    time.sleep(0.05)
                    result = self.root(["ip", "netns", "pids", name], check=False)
                    pids = [str(int(value)) for value in result.stdout.split()]
                if pids:
                    self.root(["kill", "-KILL", "--", *pids])
                    deadline = time.monotonic() + 2
                    while pids and time.monotonic() < deadline:
                        time.sleep(0.05)
                        result = self.root(["ip", "netns", "pids", name], check=False)
                        pids = [str(int(value)) for value in result.stdout.split()]
                    if pids:
                        errors.append(f"Processes still occupy namespace {name}: {pids}.")
            except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as error:
                errors.append(str(error))
        if self.service_process is not None:
            try:
                self.service_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                errors.append("Service launcher did not finish after namespace processes were stopped.")
        if self.service_log is not None:
            self.service_log.close()
        for name in self.namespaces:
            try:
                self.root(["ip", "netns", "delete", name], check=False)
                remaining = {line.split()[0] for line in self.root(["ip", "netns", "list"]).stdout.splitlines()}
                if name in remaining:
                    raise RuntimeError(f"Namespace {name} remains after cleanup.")
            except (OSError, subprocess.SubprocessError, RuntimeError) as error:
                errors.append(str(error))
        for directory in self.config_dirs:
            try:
                self.root(["rm", "-f", "--", str(directory / "hosts"), str(directory / "resolv.conf")])
                self.root(["rmdir", "--", str(directory)])
            except (OSError, subprocess.SubprocessError, RuntimeError) as error:
                errors.append(str(error))
        if self.link_created:
            try:
                links = {item["ifname"] for item in json.loads(self.root(["ip", "-j", "link", "show"]).stdout)}
                for name in self.links:
                    if name in links:
                        self.root(["ip", "link", "delete", name])
            except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as error:
                errors.append(str(error))
        try:
            write_json(self.directory / "lab-commands.json", self.commands)
        except OSError as error:
            errors.append(str(error))
        return errors


def source_metadata(checkout: Path) -> dict:
    paths = [checkout / "hylianscan.py", checkout / "pyproject.toml"]
    for directory in ("core", "modules"):
        paths.extend(sorted((checkout / directory).rglob("*.py")))
    paths.append(checkout / "modules/provider_compatibility.json")
    hashes = {str(path.relative_to(checkout)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in paths if path.is_file()}
    metadata = {"path": str(checkout), "source_files_sha256": hashes,
                "source_sha256": hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest(),
                "commit": None, "git_status": None, "diff_sha256": None}
    if shutil.which("git"):
        head = run(["git", "rev-parse", "HEAD"], cwd=checkout, check=False)
        if head.returncode == 0:
            metadata["commit"] = head.stdout.strip()
            metadata["git_status"] = run(["git", "status", "--short"], cwd=checkout).stdout.splitlines()
            # Store a fingerprint, never arbitrary workspace diff contents or secrets.
            diff = run(["git", "diff", "HEAD", "--", "hylianscan.py", "core", "modules", "pyproject.toml"], cwd=checkout)
            metadata["diff_sha256"] = hashlib.sha256(diff.stdout.encode()).hexdigest()
    return metadata


def environment_metadata(args: argparse.Namespace) -> dict:
    cpu_info = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    memory = Path("/proc/meminfo").read_text(encoding="utf-8")
    metadata = {
        "platform": platform.platform(), "kernel": platform.release(),
        "os_release": platform.freedesktop_os_release(), "architecture": platform.machine(),
        "cpu_count": os.cpu_count(), "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "cpu_model": next((line.split(":", 1)[1].strip() for line in cpu_info.splitlines()
                           if line.startswith("model name")), None),
        "memory_total": next((line for line in memory.splitlines() if line.startswith("MemTotal:")), None),
        "python": run([args.python, "--version"]).stdout.strip(), "python_executable": args.python,
        "uid": os.getuid(), "gid": os.getgid(), "vm_notes": args.vm_notes,
        "virtualization": None, "tools": {},
        "cache_policy": "Fresh namespaces/services per execution; OS page/bytecode caches stay warm; no global cache flushing.",
        "phase_timings": {"discovery_seconds": None, "probing_seconds": None,
                          "reason": "The quiet CLI exports their combined native scan duration only."},
    }
    if shutil.which("systemd-detect-virt"):
        metadata["virtualization"] = run(["systemd-detect-virt"], check=False).stdout.strip()
    return metadata


def read_hyperfine(path: Path) -> dict:
    results = json.loads(path.read_text(encoding="utf-8"))["results"]
    if len(results) != 1 or len(results[0]["times"]) != 1 or results[0]["exit_codes"] != [0]:
        raise ValueError("Expected exactly one successful Hyperfine timing sample.")
    result = results[0]
    memory = result.get("memory_usage_byte")
    metrics = {"execution_seconds": result["times"][0], "cpu_user_seconds": result["user"],
               "cpu_system_seconds": result["system"],
               "peak_memory_bytes": memory[0] if memory is not None and len(memory) == 1 else None}
    for key, value in metrics.items():
        if value is not None and (not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0):
            raise ValueError(f"Invalid Hyperfine measurement: {key}.")
    return metrics


def preflight(args: argparse.Namespace, directory: Path) -> dict:
    if sys.platform != "linux":
        raise RuntimeError("The real benchmark requires Linux namespaces. Run this command inside your Kali VM.")
    if os.geteuid() == 0:
        raise RuntimeError("Run the harness as an ordinary user; it uses sudo only for laboratory operations.")
    required = ["sudo", "ip", "nft", "setpriv", "hyperfine", "env", "install", "kill", "rm", "rmdir"]
    if args.delay_ms:
        required.append("tc")
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        raise RuntimeError("Missing laboratory executables: " + ", ".join(missing))
    metadata = environment_metadata(args)
    metadata["disk"] = disk_preflight(directory, args)
    version_flags = {"ip": "-Version", "nft": "--version", "setpriv": "--version",
                     "hyperfine": "--version"}
    if args.delay_ms:
        version_flags["tc"] = "-Version"
    for tool, flag in version_flags.items():
        result = run([tool, flag])
        metadata["tools"][tool] = {"path": shutil.which(tool), "version": (result.stdout + result.stderr).strip()}
    help_text = run(["hyperfine", "--help"]).stdout
    for flag in ("--shell", "--runs", "--warmup", "--export-json", "--output"):
        if flag not in help_text:
            raise RuntimeError(f"Installed Hyperfine does not support {flag}.")
    setpriv_help = run(["setpriv", "--help"]).stdout
    for flag in ("--reuid", "--regid", "--init-groups", "--inh-caps", "--ambient-caps",
                 "--bounding-set", "--no-new-privs"):
        if flag not in setpriv_help:
            raise RuntimeError(f"Installed setpriv does not support {flag}.")
    run(["nft", "--help"])
    probe_path = directory / "hyperfine-capabilities.json"
    run(["hyperfine", "--shell=none", "--runs", "1", "--warmup", "0", "--export-json",
         str(probe_path), shlex.join([args.python, "-c", "pass"])])
    metadata["native_peak_memory"] = read_hyperfine(probe_path)["peak_memory_bytes"] is not None
    if not metadata["native_peak_memory"]:
        if not Path("/usr/bin/time").is_file():
            raise RuntimeError("This Hyperfine build lacks peak-memory export; install GNU Time (apt install time).")
        version = run(["/usr/bin/time", "--version"])
        if "GNU" not in version.stdout + version.stderr:
            raise RuntimeError("The memory companion requires GNU /usr/bin/time.")
        metadata["tools"]["time"] = {"path": "/usr/bin/time", "version": version.stdout.strip()}
    # Inherit the terminal so sudo's authentication prompt remains visible.
    authentication = subprocess.run(["sudo", "-v"], timeout=120, check=False)
    if authentication.returncode:
        raise RuntimeError("Sudo authentication failed; no laboratory was created.")
    return metadata


def execute_sample(report: dict, args: argparse.Namespace, case: Scenario,
                   variant: str, checkout: Path, role: str, index: int,
                   *, parent_id: str | None = None) -> dict:
    sample_id = f"{len(report['samples']):04d}-{case.name}-{variant}-{role}-{index}"
    directory = Path(report["directory"]) / sample_id
    directory.mkdir()
    config = case.config(args)
    command = [args.python, str(checkout / "hylianscan.py"), TARGET, "--ipv4", "--quiet",
               "--http-probing", "--ports", port_expression(case.ports),
               "--threads", str(args.workers), "--timeout", str(args.timeout),
               "--json-output", "scan.json", "--output", "scan.txt"]
    if args.max_rate is not None:
        command.extend(["--max-rate", str(args.max_rate)])
    sample = {"id": sample_id, "scenario": case.name, "variant": variant, "role": role,
              "index": index, "parent_id": parent_id, "directory": str(directory),
              "command": command, "command_display": shlex.join(command), "cwd": str(directory),
              "status": "running", "validation_errors": [], "cleanup_errors": [], "metrics": {}}
    report["samples"].append(sample)
    lab = Lab(directory, config, args.python)
    started = time.perf_counter()
    caught: BaseException | None = None
    print(f"[{role}] {case.name}: {variant}, sample {index}", flush=True)
    try:
        sample["disk_preflight"] = disk_preflight(directory, args)
        lab.prepare()
        if role == "resources":
            resource_path = directory / "resources.json"
            if args.diagnostic_profile:
                command = [args.python, str(ROOT / "benchmark/cli_profile.py"),
                           "--output", str(directory / "cli-stages.json"), "--", *command[1:]]
            if args.resources:
                measured = resource_command(args, resource_path, command)
            else:
                fmt = ('{"execution_seconds":%e,"cpu_user_seconds":%U,'
                       '"cpu_system_seconds":%S,"peak_memory_kib":%M}')
                measured = ["/usr/bin/time", "--format", fmt, "--output", str(resource_path), *command]
        else:
            measured = ["hyperfine", "--shell=none", "--runs", "1", "--warmup", "0",
                        "--style", "basic", "--export-json", str(directory / "hyperfine.json"),
                        "--output", str(directory / "hylianscan.log"), shlex.join(command)]
        sample["launcher_command"] = lab.user_command(lab.scanner, measured)
        process = run(sample["launcher_command"], cwd=directory, timeout=args.run_timeout, check=False)
        report["validation"]["real_lab_executed"] = True
        report["validation"]["kali_lab_executed"] = report.get("environment", {}).get("os_release", {}).get("ID") == "kali"
        (directory / "launcher.log").write_text(process.stdout + process.stderr, encoding="utf-8")
        sample["exit_code"] = process.returncode
        if process.returncode:
            raise RuntimeError(f"Measured execution exited {process.returncode}; see {directory / 'launcher.log'}.")
        if role == "resources":
            metrics = json.loads(resource_path.read_text(encoding="utf-8"))
            if not args.resources:
                metrics["peak_memory_bytes"] = metrics.pop("peak_memory_kib") * 1024
                metrics["measurement_source"] = "gnu_time_companion"
            sample["cleanup_errors"].extend(metrics.get("cleanup_errors", []))
        else:
            metrics = read_hyperfine(directory / "hyperfine.json")
            metrics["measurement_source"] = "hyperfine"
        document = json.loads((directory / "output/scan.json").read_text(encoding="utf-8"))
        duration = document["scan"]["timing"]["duration_seconds"]
        if not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration < 0:
            raise ValueError("Invalid native scan duration.")
        metrics["native_scan_seconds"] = duration
        sample["metrics"] = metrics
        counters = lab.counters()
        write_json(directory / "drop-after.json", counters)
        sample["validation_errors"] = validate_document(document, case, counters)
        sample["validation_errors"].extend(validate_text(
            (directory / "scan.txt").read_text(encoding="utf-8"), case))
        if lab.service_process.poll() is not None:
            sample["validation_errors"].append("Laboratory services exited during measurement.")
        sample["status"] = "failed" if sample["validation_errors"] else "completed"
        if sample["validation_errors"]:
            raise RuntimeError("; ".join(sample["validation_errors"]))
    except BaseException as error:
        caught = error
        sample["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        sample["error"] = f"{type(error).__name__}: {error}"
    finally:
        # A second Ctrl+C must not interrupt the cleanup that the first one requested.
        previous = {signum: signal.signal(signum, signal.SIG_IGN) for signum in (signal.SIGINT, signal.SIGTERM)}
        try:
            try:
                sample["cleanup_errors"].extend(lab.close())
            except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as error:
                sample["cleanup_errors"].append(f"Cleanup failed: {error}")
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
        sample["total_sample_seconds"] = time.perf_counter() - started
        stats_path = directory / "services.json"
        if stats_path.is_file():
            try:
                stats = json.loads(stats_path.read_text(encoding="utf-8"))
                if not isinstance(stats["errors"], list):
                    raise ValueError("Expected an error list.")
                sample["service_statistics"] = stats
                sample["validation_errors"].extend(str(error) for error in stats["errors"])
            except (OSError, ValueError, KeyError, TypeError) as error:
                sample["validation_errors"].append(f"Service telemetry is invalid: {error}")
        else:
            sample["validation_errors"].append("Service telemetry was not recovered.")
        if sample["cleanup_errors"] or sample["validation_errors"]:
            sample["status"] = "failed" if caught is None else sample["status"]
        write_json(directory / "sample.json", sample)
    if caught is not None:
        raise caught
    if sample["status"] != "completed":
        raise RuntimeError(f"Laboratory cleanup/telemetry failed: {sample_id}.")
    return sample


def sample_bundle(report: dict, args: argparse.Namespace, case: Scenario, variant: str,
                  checkout: Path, role: str, index: int) -> float:
    started = time.perf_counter()
    sample = execute_sample(report, args, case, variant, checkout, role, index)
    if (args.resources or sample["metrics"]["peak_memory_bytes"] is None) and role != "warmup":
        companion = execute_sample(report, args, case, variant, checkout, "resources", index,
                                   parent_id=sample["id"])
        sample["memory_companion_id"] = companion["id"]
        write_json(Path(sample["directory"]) / "sample.json", sample)
    return time.perf_counter() - started


def resource_command(args: argparse.Namespace, path: Path, command: list[str]) -> list[str]:
    return [args.python, str(ROOT / "benchmark/resources.py"), "--output", str(path),
            "--timeout", str(max(1, args.run_timeout - 10)), "--", *command]


def repetitions(args: argparse.Namespace, cases: list[Scenario], costs: dict[str, float],
                elapsed: float) -> dict:
    counts = {}
    for case in cases:
        if case.name == "scaling-all":
            counts[case.name] = args.full_runs
        elif case.slow:
            counts[case.name] = args.slow_runs or (3 if args.profile == "quick" else 10)
        else:
            counts[case.name] = args.fast_runs or (7 if args.profile == "quick" else 30)
    warmup_cost = sum(costs.values()) * args.warmups
    if args.profile == "quick":
        adjustable = [case.name for case in cases
                      if (args.slow_runs if case.slow else args.fast_runs) is None]
        while elapsed + warmup_cost + sum(costs[name] * count for name, count in counts.items()) > args.budget_seconds:
            choices = [name for name in adjustable if counts[name] > 2]
            if not choices:
                break
            name = max(choices, key=lambda value: costs[value] * counts[value])
            counts[name] -= 1
    estimated = elapsed + warmup_cost + sum(costs[name] * count for name, count in counts.items())
    return {"repetitions": counts, "pilot_bundle_seconds": costs, "estimated_battery_seconds": estimated,
            "target_seconds": args.budget_seconds if args.profile == "quick" else None,
            "target_feasible": estimated <= args.budget_seconds if args.profile == "quick" else None,
            "note": "Pilot estimates include setup, validation, cleanup, and memory companions. All cases retain at least two measured samples."}


def summarize(report: dict) -> list[dict]:
    rows = []
    subdomain = report.get("benchmark") == "subdomain"
    for case in report["scenarios"]:
        for variant in report["versions"]:
            samples = [sample for sample in report["samples"] if sample["scenario"] == case["name"]
                       and sample["variant"] == variant and sample["role"] == "measured"
                       and sample["status"] == "completed"]
            companions = [sample for sample in report["samples"] if sample["role"] == "resources"
                          and sample["status"] == "completed"
                          and sample["parent_id"] in {sample["id"] for sample in samples}]
            metrics = ("execution_seconds", "merge_seconds", "txt_write_seconds",
                       "json_write_seconds", "json_build_seconds", "cpu_user_seconds", "cpu_system_seconds",
                       "peak_memory_bytes") if subdomain else (
                "execution_seconds", "native_scan_seconds", "cpu_user_seconds", "cpu_system_seconds", "peak_memory_bytes")
            metrics += ("sampled_tree_peak_rss_bytes", "sampled_tree_peak_descriptors", "sampled_tree_peak_processes")
            for metric in metrics:
                source = samples
                if companions and (metric == "peak_memory_bytes" or metric.startswith("sampled_tree_")
                                   or subdomain and metric.startswith("cpu_")):
                    source = companions
                values = [sample["metrics"][metric] for sample in source
                          if sample["metrics"].get(metric) is not None]
                if values:
                    rows.append({"scenario": case["name"], "variant": variant, "metric": metric,
                                 "source": (source[0]["metrics"].get("measurement_source", "gnu_time_companion") if source is companions else
                                            "stdlib_perf_counter" if subdomain else
                                            "hylianscan_json" if metric == "native_scan_seconds" else "hyperfine"),
                                 "count": len(values), "mean": statistics.mean(values),
                                 "median": statistics.median(values), "min": min(values), "max": max(values),
                                 "stddev": statistics.stdev(values) if len(values) > 1 else None})
    return rows


def paired_comparisons(report: dict) -> list[dict]:
    """Retain pair/order observations without declaring statistical significance."""
    groups = {}
    for sample in report["samples"]:
        if sample["role"] == "measured" and sample["status"] == "completed":
            groups.setdefault((sample["scenario"], sample.get("index")), []).append(sample)
    rows = []
    for (scenario, index), samples in groups.items():
        variants = {sample["variant"]: sample for sample in samples}
        if len(samples) != 2 or set(variants) != {"reference", "candidate"}:
            continue
        reference = variants["reference"]["metrics"]["execution_seconds"]
        candidate = variants["candidate"]["metrics"]["execution_seconds"]
        rows.append({"scenario": scenario, "index": index,
                     "order": "/".join(sample["variant"] for sample in samples),
                     "reference_seconds": reference, "candidate_seconds": candidate,
                     "change_percent": (candidate / reference - 1) * 100 if reference else None,
                     "valid": report["status"] == "completed"})
    return rows


def comparisons(report: dict, threshold: float | None) -> list[dict]:
    rows = []
    if "reference" not in report["versions"]:
        return rows
    medians = {(row["scenario"], row["variant"]): row["median"] for row in report["summary"]
               if row["metric"] == "execution_seconds"}
    valid = report["status"] == "completed"
    for case in report["scenarios"]:
        eligible = valid and case.get("comparison_eligible", True)
        baseline = medians.get((case["name"], "reference"))
        candidate = medians.get((case["name"], "candidate"))
        delta = (candidate / baseline - 1) * 100 if baseline and candidate is not None else None
        # ponytail: a configured median threshold, add confidence intervals if A/A noise warrants it.
        rows.append({"scenario": case["name"], "valid": eligible, "change_percent": delta,
                     "threshold_percent": threshold,
                     "regressed": delta > threshold if eligible and delta is not None and threshold is not None else None})
    return rows


def write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def save_report(report: dict, elapsed: float, threshold: float | None) -> None:
    report["total_battery_seconds"] = elapsed
    report["summary"] = summarize(report)
    report["comparisons"] = comparisons(report, threshold)
    report["paired_comparisons"] = paired_comparisons(report)
    directory = Path(report["directory"])
    write_json(directory / "report.json", report)
    sample_rows = [{**sample, **{key: json.dumps(value, sort_keys=True) if isinstance(value, dict) else value
                               for key, value in sample["metrics"].items()}, "total_battery_seconds": elapsed,
                    "providers": json.dumps(sample.get("providers", {}), sort_keys=True),
                    "command": json.dumps(sample.get("command", [])),
                    "cli_command": json.dumps(sample.get("cli_command", [])),
                    "validation_errors": "; ".join(sample["validation_errors"]),
                    "cleanup_errors": "; ".join(sample["cleanup_errors"])} for sample in report["samples"]]
    metric_fields = (["unique_in_scope", "invalid_or_out_of_scope", "subfinder_count", "amass_count",
                      "overlap", "subfinder_exclusive", "amass_exclusive", "providers", "command", "cwd",
                      "cli_command", "workload_sha256", "comparison_eligible", "expected_exit_code", "observed_exit_code",
                      "expected_outcome", "merge_seconds", "txt_write_seconds", "json_write_seconds", "json_build_seconds",
                      "first_candidate_seconds", "received_lines", "accepted_unique", "saved_unique", "emitted_records",
                      "emitted_stdout_bytes", "emitted_stderr_bytes", "peak_memory_bytes", "memory_reason", "error"]
                     if report.get("benchmark") == "subdomain" else
                     ["native_scan_seconds", "cpu_user_seconds", "cpu_system_seconds", "peak_memory_bytes"])
    metric_fields += ["sampled_tree_peak_rss_bytes", "sampled_tree_peak_descriptors",
                      "sampled_tree_peak_processes", "traffic"]
    if report.get("benchmark") == "subdomain":
        metric_fields += ["cpu_user_seconds", "cpu_system_seconds"]
    write_csv(directory / "samples.csv", ["id", "scenario", "variant", "role", "parent_id", "status",
              "exit_code", "execution_seconds", *metric_fields, "measurement_source", "total_sample_seconds", "total_battery_seconds",
              "validation_errors", "cleanup_errors", "directory"], sample_rows)
    write_csv(directory / "summary.csv", ["scenario", "variant", "metric", "source", "count", "mean",
                                         "median", "min", "max", "stddev"], report["summary"])
    write_csv(directory / "battery.csv", ["status", "benchmark", "profile", "total_battery_seconds", "error", "directory"], [report])
    write_csv(directory / "comparison.csv", ["scenario", "valid", "change_percent", "threshold_percent", "regressed"],
              report["comparisons"])
    write_csv(directory / "pairs.csv", ["scenario", "index", "order", "reference_seconds",
                                       "candidate_seconds", "change_percent", "valid"], report["paired_comparisons"])


def run_tcp_scan(args: argparse.Namespace) -> int:
    args = resolve_options(args)
    cases = scenarios(args)
    timestamp = build_timestamp() + "_" + uuid.uuid4().hex[:8]
    directory = ((args.output_dir.resolve() / timestamp) if args.output_dir else
                 resolve_output_workspace("benchmark", timestamp=timestamp))
    directory.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    report = {"schema": {"name": "hylianscan_benchmark", "version": 1}, "directory": str(directory),
              "started_utc": timestamp, "status": "running", "benchmark": args.benchmark, "profile": args.profile,
              "options": {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()},
              "versions": {}, "scenarios": [asdict(case) for case in cases], "samples": [],
              "validation": {"real_lab_executed": False, "kali_lab_executed": False, "battery_completed": False}}
    variants = [("candidate", args.candidate)]
    if args.reference:
        variants.insert(0, ("reference", args.reference))
    if args.first_variant == "candidate":
        variants.reverse()

    def interrupt(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    previous = {signum: signal.signal(signum, interrupt) for signum in (signal.SIGINT, signal.SIGTERM)}
    exit_code = 0
    try:
        report["environment"] = preflight(args, directory)
        report["versions"] = {name: source_metadata(checkout) for name, checkout in variants}
        report["harness_sha256"] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in sorted((ROOT / "scripts").glob("benchmark*.py"))}
        costs = {}
        for case in cases:
            costs[case.name] = sum(sample_bundle(report, args, case, name, checkout, "pilot", 0)
                                   for name, checkout in variants)
            save_report(report, time.perf_counter() - started, args.regression_percent)
        report["calibration"] = repetitions(args, cases, costs, time.perf_counter() - started)
        print(f"Pilot estimates {report['calibration']['estimated_battery_seconds']:.1f}s for this battery.", flush=True)
        if report["calibration"]["target_feasible"] is False:
            print("Quick target cannot be met with these settings; retaining coverage and explicit overrides.", flush=True)
        for case in cases:
            for index in range(args.warmups):
                for name, checkout in variants:
                    sample_bundle(report, args, case, name, checkout, "warmup", index + 1)
                    save_report(report, time.perf_counter() - started, args.regression_percent)
            for index in range(report["calibration"]["repetitions"][case.name]):
                # Alternating order controls drift without simultaneous scanner load.
                order = variants if index % 2 == 0 else list(reversed(variants))
                for name, checkout in order:
                    sample_bundle(report, args, case, name, checkout, "measured", index + 1)
                    save_report(report, time.perf_counter() - started, args.regression_percent)
        report["status"] = "completed"
        report["validation"]["battery_completed"] = True
    except KeyboardInterrupt:
        report["status"], report["error"], exit_code = "interrupted", "Battery interrupted; collected evidence retained.", 130
    except Exception as error:
        report["status"], report["error"], exit_code = "failed", f"{type(error).__name__}: {error}", 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        save_report(report, time.perf_counter() - started, args.regression_percent)
    if any(row["regressed"] is True for row in report["comparisons"]):
        exit_code = 2
        report["performance_regression"] = True
        save_report(report, time.perf_counter() - started, args.regression_percent)
    print(f"Battery {report['status']}: {report['total_battery_seconds']:.1f}s total. Reports: {directory}")
    if report.get("error"):
        print(report["error"], file=sys.stderr)
    return exit_code


# Only implemented benchmarks belong here; help and dispatch share this registry.
def run_subdomain(args: argparse.Namespace) -> int:
    from benchmark.subdomain import run_subdomain as runner
    return runner(args)


def run_providers(args: argparse.Namespace) -> int:
    from benchmark.providers import run_benchmark
    return run_benchmark(resolve_options(args))


BENCHMARKS = {"tcp_scan": run_tcp_scan, "subdomain": run_subdomain,
              "providers": run_providers, "dnsx": run_providers}


def main(argv: list[str] | None = None) -> int:
    cli = parser()
    args = cli.parse_args(argv)
    try:
        return BENCHMARKS[args.benchmark](args)
    except ValueError as error:
        cli.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
