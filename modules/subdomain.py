"""Passive subdomain discovery integration for hylianscan."""

import json
import http.client
import math
import re
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from collections import deque
from collections.abc import Callable, Iterable
from contextlib import ExitStack
from dataclasses import dataclass, replace
from pathlib import Path

from modules.target import normalize_address_family
from modules.provider_compatibility import PROVIDERS, VERSION_PATTERN, classify_version, missing_flags


TelemetryCallback = Callable[[str], None]

ANSI_PATTERN = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")
# Amass 5's pb/v3 default bar has no separators when stderr is not a terminal.
AMASS_PROGRESS_PATTERN = re.compile(
    rb"\d+ / \d+ \[[=>_\- ]+\]\s+\d+(?:\.\d+)?% (?:\?|\d+(?:\.\d+)?[kMGTPEZY]?) p/s"
)
DEFAULT_PROVIDER_TIMEOUT_SECONDS = 180.0
PROVIDER_SHUTDOWN_GRACE_SECONDS = 5.0


@dataclass(frozen=True)
class ProviderRunResult:
    """Results and execution status from one passive provider."""

    subdomains: list[str]
    status: str
    exit_code: int | None = None
    reason: str | None = None
    metadata: list[dict[str, object]] | None = None
    diagnostics: tuple[str, ...] = ()
    elapsed_seconds: float | None = None
    compatibility: dict[str, str] | None = None


class ProviderInterrupted(KeyboardInterrupt):
    """Carry already collected evidence through cancellation."""

    def __init__(self, result: ProviderRunResult):
        super().__init__("Passive provider interrupted")
        self.result = result


def build_provider_missing_message(provider_name: str, path_option: str) -> str:
    """Build a clear provider installation/path hint."""
    return (
        f"{provider_name} executable was not found. Install {provider_name} and "
        f"make it available in PATH, or provide the executable path manually with "
        f"{path_option}."
    )


def resolve_provider_executable(
    provider_name: str,
    default_command: str,
    path_option: str,
    explicit_path: str | None = None,
) -> str:
    """Resolve a passive provider executable from PATH or an explicit path."""
    if explicit_path:
        executable_path = Path(explicit_path).expanduser()

        if not executable_path.exists():
            raise ValueError(
                f"{provider_name} executable path does not exist: {executable_path}. "
                f"Provide a valid executable file with {path_option}."
            )

        if not executable_path.is_file() or not os.access(executable_path, os.X_OK):
            raise ValueError(
                f"{provider_name} executable path is not executable: {executable_path}. "
                f"Provide an executable file with {path_option}."
            )

        return str(executable_path)

    if shutil.which(default_command) is None:
        raise ValueError(build_provider_missing_message(provider_name, path_option))

    return default_command


def clean_terminal_text(value: str) -> str:
    """Remove ANSI escape codes and surrounding whitespace from tool output."""
    return re.sub(r"[\x00-\x1f\x7f]", " ", ANSI_PATTERN.sub("", value)).strip()


def clean_subdomain(value: str) -> str | None:
    """Normalize one provider stdout line into a subdomain candidate."""
    candidate = clean_terminal_text(value).lower().strip(".")

    if not candidate or "." not in candidate:
        return None

    if any(character.isspace() for character in candidate):
        return None

    return candidate


def scoped_subdomain(value: str, domain: str) -> str | None:
    """Accept only DNS hostnames inside the requested discovery domain."""
    candidate = clean_subdomain(value)
    root = domain.lower().rstrip(".")
    if candidate is None or len(candidate) > 253:
        return None
    if candidate.rsplit(".", 1)[-1].isdigit():
        return None
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
               for label in candidate.split(".")):
        return None
    if domain and candidate != root and not candidate.endswith("." + root):
        return None
    return candidate


def stop_provider(process: subprocess.Popen) -> None:
    """Stop owned processes without an unbounded wait or pipe drain."""
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        # Windows has no killpg; taskkill handles children of the owned process.
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=PROVIDER_SHUTDOWN_GRACE_SECONDS,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
    try:
        process.wait(timeout=PROVIDER_SHUTDOWN_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=PROVIDER_SHUTDOWN_GRACE_SECONDS)
    finally:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def run_passive_provider(
    domain: str,
    provider_name: str,
    command: list[str],
    telemetry_callback: TelemetryCallback | None = None,
    timeout: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    input_text: str | None = None,
    output_parser: Callable[[str], str | Iterable[str] | None] | None = None,
    stderr_callback: Callable[[str], None] | None = None,
    stderr_filter: Callable[[bytes], bytes] | None = None,
    deferred_results: bool = False,
) -> ProviderRunResult:
    """Poll file-backed output so input and inherited pipes cannot block a deadline."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Provider timeout must be a finite positive number.")
    if domain and scoped_subdomain(domain, domain) is None:
        raise ValueError("Passive discovery requires a valid DNS domain name.")
    seen: set[str] = set()
    diagnostics: deque[str] = deque(maxlen=20)
    status, reason = "completed", None
    interrupted = False
    next_diagnostic = 0.0

    def emit(message: str) -> None:
        if telemetry_callback is not None and not interrupted:
            telemetry_callback(message)

    def candidate_status() -> str:
        return "count pending graph query" if deferred_results else f"{len(seen)} candidates"

    def handle_line(line: str, stderr: bool) -> None:
        nonlocal next_diagnostic
        line = clean_terminal_text(line)
        if not line:
            return
        if stderr:
            if stderr_callback is not None:
                stderr_callback(line)
            diagnostics.append(line[:2000])
            # Prefix untrusted output so it cannot impersonate lifecycle events.
            now = time.monotonic()
            if now >= next_diagnostic:
                emit(f"{provider_name} stderr: {line[:2000]}")
                next_diagnostic = now + 1
            return
        parsed = output_parser(line) if output_parser else line
        for candidate in ([parsed] if isinstance(parsed, str) else parsed or []):
            hostname = scoped_subdomain(candidate, domain)
            if hostname and hostname not in seen:
                seen.add(hostname)
                if len(seen) == 1:
                    emit(f"{provider_name} first result observed")

    with ExitStack() as stack:
        stdin = stack.enter_context(tempfile.TemporaryFile())
        stdin.write((input_text or "").encode("utf-8"))
        stdin.seek(0)
        writers, readers = [], []
        for _ in range(2):
            writer = stack.enter_context(tempfile.NamedTemporaryFile())
            # O_TEMPORARY shares delete access on Windows, including inherited handles.
            fd = os.open(writer.name, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                         | getattr(os, "O_TEMPORARY", 0))
            readers.append(stack.enter_context(os.fdopen(fd, "rb")))
            writers.append(writer)
        pending = [b"", b""]

        def drain(final: bool = False) -> None:
            for index, reader in enumerate(readers):
                # Snapshot the length: a surviving descendant cannot extend this drain.
                remaining = os.fstat(reader.fileno()).st_size - reader.tell()
                if not final:
                    remaining = min(remaining, 65536)
                while remaining > 0:
                    chunk = reader.read(min(remaining, 65536))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    buffered = pending[index] + chunk
                    if index and stderr_filter is not None:
                        buffered = stderr_filter(buffered)
                    lines = re.split(rb"[\r\n]", buffered)
                    pending[index] = lines.pop()
                    for line in lines:
                        handle_line(line.decode("utf-8", errors="replace"), bool(index))
                    # ponytail: cap unterminated lines at 1 MiB; use structured files for larger records.
                    if len(pending[index]) > 1048576:
                        pending[index] = b""
                        diagnostics.append("Dropped provider line exceeding 1 MiB.")
                if final and pending[index]:
                    handle_line(pending[index].decode("utf-8", errors="replace"), bool(index))
                    pending[index] = b""

        started = time.monotonic()
        try:
            process = subprocess.Popen(
                command, stdin=stdin, stdout=writers[0], stderr=writers[1],
                start_new_session=os.name == "posix",
            )
        except OSError as error:
            raise ValueError(f"Unable to start {provider_name}: {error}") from error
        try:
            emit(f"{provider_name} provider started")
            next_progress = started
            while True:
                drain()
                now = time.monotonic()
                return_code = process.poll()
                if return_code is not None:
                    break
                if now - started >= timeout:
                    status = "timed_out"
                    reason = f"Timed out after {timeout:g} seconds."
                    break
                if now >= next_progress:
                    emit(f"{provider_name} progress: {now - started:.0f}s / {timeout:g}s; {candidate_status()}")
                    next_progress = now + 5
                time.sleep(min(0.05, max(0, timeout - (now - started))))
        except KeyboardInterrupt:
            status, reason = "interrupted", "Interrupted by user."
            interrupted = True
        finally:
            # Also remove owned POSIX descendants after a wrapper exits normally.
            try:
                if process.poll() is None or os.name == "posix":
                    stop_provider(process)
                drain(final=True)
            except KeyboardInterrupt:
                status, reason = "interrupted", "Interrupted by user."
                interrupted = True
                stop_provider(process)
                drain(final=True)

        if status == "completed" and return_code != 0:
            status, reason = "failed", f"Exited with status code {return_code}."
        result = ProviderRunResult(
            sorted(seen), status,
            return_code if status in {"completed", "failed"} else None,
            reason, diagnostics=tuple(diagnostics),
            elapsed_seconds=round(time.monotonic() - started, 3),
        )
    if status != "completed":
        warning = f"[-] {provider_name}: {reason[0].lower() + reason[1:]} Returning partial results."
        if telemetry_callback is None:
            print(warning, file=sys.stderr)
        emit(f"{provider_name} provider {status}: {reason}")
    else:
        emit(f"{provider_name} provider completed: exit 0; {candidate_status()}")
    if interrupted:
        raise ProviderInterrupted(result)
    return result


def inspect_provider_compatibility(
    provider: str, executable: str, timeout: float = 10.0,
) -> dict[str, str]:
    """Describe local compatibility without blocking discovery on version policy."""
    spec = PROVIDERS[provider]
    started = time.monotonic()

    def capture(arguments: list[str]) -> tuple[str, str | None]:
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            return "", "Compatibility check budget exhausted."
        lines: deque[str] = deque(maxlen=1024)
        result = run_passive_provider(
            "", f"{spec['name']} compatibility", [executable, *arguments],
            timeout=remaining, output_parser=lambda line: lines.append(line[:2000]),
            stderr_callback=lambda line: lines.append(line[:2000]),
        )
        if result.status != "completed":
            return "\n".join(lines), result.reason or result.status
        return "\n".join(lines), None

    output, version_error = capture(spec["version_args"])
    versions = {match.group(1) for match in VERSION_PATTERN.finditer(output)}
    version = versions.pop() if len(versions) == 1 and version_error is None else "unknown"
    status = classify_version(provider, version) if version != "unknown" else "unverified"
    reasons = []
    if version_error:
        reasons.append(f"Version command failed: {version_error}")
    elif version == "unknown":
        reasons.append("Version output was missing or ambiguous.")
    elif status == "unsupported":
        reasons.append(spec.get("unsupported_reason", "Version is outside supported majors."))

    commands = ""
    if provider == "amass" and (version.startswith("5.") or version == "unknown"):
        commands, commands_error = capture(["-h"])
        if commands_error:
            raise ValueError(f"Unable to verify Amass subcommands: {commands_error}")
    v5_help = provider == "amass" and (version.startswith("5.") or
                                         (version == "unknown" and "engine" in commands and "subs" in commands))
    if v5_help:
        missing_commands = [name for name in spec["required_subcommands_v5"]
                            if not re.search(rf"\b{name}\b", commands)]
        if missing_commands:
            raise ValueError(f"Amass {version} is missing required subcommands: "
                             f"{', '.join(missing_commands)}.")
        help_output, help_error = capture(["subs", "-h"])
        required = spec["required_flags_v5"]
    else:
        help_output, help_error = capture(spec["help_args"])
        required = None
    missing = missing_flags(provider, help_output, required)
    if help_error:
        raise ValueError(f"Unable to verify {spec['name']} required options: {help_error}")
    if missing:
        raise ValueError(f"{spec['name']} {version} is missing required options: {', '.join(missing)}.")

    result = {"version": version, "status": status, "executable": executable}
    if reasons:
        result["reason"] = " ".join(reasons)
    return result


def run_subfinder(
    domain: str,
    telemetry_callback: TelemetryCallback | None = None,
    timeout: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    executable_path: str | None = None,
) -> ProviderRunResult:
    """Run Subfinder passive discovery and return clean subdomain results."""
    executable = resolve_provider_executable(
        provider_name="Subfinder",
        default_command="subfinder",
        path_option="--subfinder-path",
        explicit_path=executable_path,
    )

    return run_passive_provider(
        domain=domain,
        provider_name="Subfinder",
        command=[executable, "-d", domain, "-silent"],
        telemetry_callback=telemetry_callback,
        timeout=timeout,
    )


def run_amass(
    domain: str,
    telemetry_callback: TelemetryCallback | None = None,
    timeout: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    executable_path: str | None = None,
) -> ProviderRunResult:
    """Run Amass passive discovery and return clean subdomain results."""
    executable = resolve_provider_executable(
        provider_name="Amass",
        default_command="amass",
        path_option="--amass-path",
        explicit_path=executable_path,
    )
    started = time.monotonic()
    version_lines: list[str] = []
    version_result = run_passive_provider(
        "", "Amass version", [executable, "-version"],
        timeout=min(timeout, 10), output_parser=lambda line: version_lines.append(line),
    )
    version = VERSION_PATTERN.search("\n".join([*version_lines, *version_result.diagnostics]))
    if version_result.status != "completed" or version is None:
        return ProviderRunResult([], "failed", reason="Unable to verify Amass version.",
                                 diagnostics=version_result.diagnostics)
    if classify_version("amass", version.group(1)) == "unsupported":
        return ProviderRunResult(
            [], "failed", reason=(
                f"Amass {version.group(0)} is unsupported. Use Amass 3.x, 4.x, or 5.x "
                "with --amass-path."
            ),
        )
    remaining = timeout - (time.monotonic() - started)
    if remaining <= 0:
        return ProviderRunResult([], "timed_out", reason=f"Timed out after {timeout:g} seconds.")
    if version.group(1).startswith("5."):
        return _run_amass_v5(domain, executable, remaining, telemetry_callback)

    def parse_amass_line(line: str) -> list[str]:
        # Both ends may contain in-scope names (e.g. CNAME relationships).
        return re.findall(r"([^\s]+)\s+\(FQDN\)", line) or [line]

    return run_passive_provider(
        domain=domain,
        provider_name="Amass",
        command=[executable, "enum", "-passive", "-d", domain],
        telemetry_callback=telemetry_callback,
        timeout=remaining,
        output_parser=parse_amass_line,
    )


def _amass_engine_ready() -> bool:
    """Recognize the local Amass GraphQL engine without touching other services."""
    connection = http.client.HTTPConnection("127.0.0.1", 4000, timeout=0.25)
    try:
        connection.request("POST", "/graphql", '{"query":"{__typename}"}',
                           {"Content-Type": "application/json"})
        response = json.loads(connection.getresponse().read(2048))
        return isinstance(response, dict) and isinstance(response.get("data"), dict)
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def _amass_v5_config() -> Path:
    """Use Amass's own config while rejecting active enumeration settings."""
    if any(name.startswith(("AMASS_DB_", "AMASS_ENGINE_")) for name in os.environ):
        raise ValueError("Amass 5 engine/database environment overrides prevent an isolated local run.")
    configured = os.environ.get("AMASS_CONFIG")
    if configured:
        config = Path(configured).expanduser()
    elif os.name == "nt":
        config = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming")) / "amass/config.yaml"
    else:
        config = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "amass/config.yaml"
    if not config.is_file():
        raise ValueError(f"Amass 5 configuration was not found: {config}.")
    settings = "\n".join(line.split("#", 1)[0] for line in config.read_text(encoding="utf-8").splitlines())
    if re.search(r"(?im)(?:^|[,{])[ \t]*[\"']?(?:engine|database)[\"']?[ \t]*:", settings):
        raise ValueError("Amass 5 configuration uses an external engine or database; local isolated runs require defaults.")
    for match in re.finditer(r"(?im)(?:^|[,{])[ \t]*[\"']?active[\"']?[ \t]*:[ \t]*([^,\s}#]*)", settings):
        if match.group(1).lower() != "false":
            raise ValueError("Amass 5 configuration enables or ambiguously sets active enumeration.")
    section = None
    indentation = 0
    for line in settings.splitlines():
        if not line.strip():
            continue
        depth = len(line) - len(line.lstrip(" \t"))
        if section and depth <= indentation:
            section = None
        key, separator, value = line.strip().partition(":")
        if key in {"bruteforce", "alterations"} and separator:
            section, indentation = key, depth
        elif section and key == "enabled" and value.strip().lower() != "false":
            raise ValueError(f"Amass 5 configuration enables or ambiguously sets {section}.")
    return config.resolve()


def _run_amass_v5(
    domain: str, executable: str, timeout: float,
    telemetry_callback: TelemetryCallback | None,
) -> ProviderRunResult:
    """Use a managed engine and read v5 findings from its per-run graph database."""
    started = time.monotonic()
    # The v5 -passive switch does not override active settings in YAML.
    try:
        config = _amass_v5_config()
    except (OSError, ValueError) as error:
        return ProviderRunResult([], "failed", reason=str(error))
    with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as engine_log:
        engine = None
        try:
            if _amass_engine_ready():
                return ProviderRunResult([], "failed", reason=(
                    "An Amass engine is already running on 127.0.0.1:4000. "
                    "Stop it before retrying; Amass 5 cannot isolate this run on an existing engine."
                ))
            # v5 omits Config.Dir from its session JSON. The engine therefore uses
            # its own config home for assetdb.db, regardless of enum's -dir.
            graph_directory = Path(directory) / "amass"
            graph_directory.mkdir()
            engine_environment = os.environ.copy()
            engine_environment["APPDATA" if os.name == "nt" else "XDG_CONFIG_HOME"] = directory
            try:
                engine_command = [executable, "engine"]
                # Amass 5 uses ':' in engine log filenames; -log-dir fails on Windows.
                if os.name != "nt":
                    engine_command.extend(["-log-dir", directory])
                engine = subprocess.Popen(
                    engine_command,
                    stdin=subprocess.DEVNULL, stdout=engine_log, stderr=engine_log,
                    start_new_session=os.name == "posix",
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    env=engine_environment,
                )
            except OSError as error:
                return ProviderRunResult([], "failed", reason=f"Unable to start Amass engine: {error}")
            while not _amass_engine_ready():
                if engine.poll() is not None:
                    engine_log.seek(0)
                    detail = clean_terminal_text(engine_log.read(2000).decode("utf-8", "replace"))
                    return ProviderRunResult([], "failed", reason=f"Amass engine stopped: {detail}")
                if time.monotonic() - started >= min(timeout, 10):
                    return ProviderRunResult([], "timed_out", reason="Amass engine did not become ready.")
                time.sleep(0.1)

            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                return ProviderRunResult([], "timed_out", reason="Amass process budget exhausted.")
            interrupted = False
            try:
                enumeration = run_passive_provider(
                    domain, "Amass", [executable, "enum", "-passive", "-d", domain,
                                      "-dir", str(graph_directory), "-config", str(config), "-nocolor"],
                    telemetry_callback=telemetry_callback, timeout=remaining,
                    stderr_filter=lambda data: AMASS_PROGRESS_PATTERN.sub(b"", data),
                    deferred_results=True,
                )
            except ProviderInterrupted as error:
                enumeration, interrupted = error.result, True
            except ValueError as error:
                enumeration = ProviderRunResult([], "failed", reason=str(error))

            # The engine writes names to its graph, including after a timed-out enum.
            query_timeout = (max(timeout - (time.monotonic() - started), PROVIDER_SHUTDOWN_GRACE_SECONDS)
                             if enumeration.status == "completed" else PROVIDER_SHUTDOWN_GRACE_SECONDS)
            try:
                names = run_passive_provider(
                    domain, "Amass results", [executable, "subs", "-names", "-d", domain,
                                             "-dir", str(graph_directory), "-config", str(config), "-nocolor"],
                    telemetry_callback=telemetry_callback, timeout=query_timeout,
                )
            except ProviderInterrupted as error:
                names, interrupted = error.result, True
            except ValueError as error:
                names = ProviderRunResult([], "failed", reason=str(error))
            status = enumeration.status if enumeration.status != "completed" else names.status
            reason = enumeration.reason if enumeration.status != "completed" else names.reason
            diagnostics = enumeration.diagnostics + names.diagnostics
            if names.status != "completed" and names.reason:
                diagnostics += (f"Amass results: {names.reason}",)
            if engine is not None:
                stop_provider(engine)
                engine = None
            # Read only after stopping our writer: inherited stdout shares its offset.
            with ExitStack() as logs:
                sources = [("engine output", engine_log)]
                for path in sorted([*Path(directory).glob("*.log"), *graph_directory.glob("*.log")]):
                    try:
                        sources.append((path.name, logs.enter_context(path.open("rb"))))
                    except OSError as error:
                        diagnostics += (f"Amass log unavailable: {error}",)
                for label, stream in sources:
                    try:
                        stream.seek(0, os.SEEK_END)
                        size = stream.tell()
                        stream.seek(max(0, size - 40000))
                        tail = stream.read(40000).decode("utf-8", "replace").splitlines()
                    except OSError as error:
                        diagnostics += (f"Amass {label} unavailable: {error}",)
                        continue
                    if size > 40000:
                        tail = tail[1:]
                    diagnostics += tuple(
                        f"Amass {label}: {clean_terminal_text(line)[:2000]}"
                        for line in tail[-20:] if clean_terminal_text(line)
                    )
            result = ProviderRunResult(
                sorted(set(enumeration.subdomains + names.subdomains)), status,
                enumeration.exit_code if enumeration.status != "completed" else names.exit_code,
                reason, diagnostics=diagnostics,
                elapsed_seconds=round(time.monotonic() - started, 3),
            )
            if interrupted:
                raise ProviderInterrupted(result)
            return result
        finally:
            if engine is not None:
                stop_provider(engine)


def run_dnsx(
    subdomains: list[str],
    telemetry_callback: TelemetryCallback | None = None,
    timeout: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    executable_path: str | None = None,
    address_family: str = "dual-stack",
    resolver: str | None = None,
    threads: int | None = None,
    rate_limit: int | None = None,
    query_timeout: float | None = None,
    retry: int | None = None,
    auto_wildcard: bool = False,
    json_output: bool = False,
) -> ProviderRunResult:
    """Return hostnames with DNSx-confirmed A and/or AAAA records."""
    metadata: list[dict[str, object]] | None = [] if json_output else None
    candidates = {clean_subdomain(name) for name in subdomains}
    executable = resolve_provider_executable(
        provider_name="DNSx",
        default_command="dnsx",
        path_option="--dnsx-path",
        explicit_path=executable_path,
    )
    if not subdomains:
        return ProviderRunResult(
            subdomains=[],
            status="skipped",
            reason="No candidate subdomains to resolve.",
            metadata=metadata,
        )

    family = normalize_address_family(address_family)
    command = [executable, "-silent", "-no-color"]

    if family != "ipv6":
        command.append("-a")
    if family != "ipv4":
        command.append("-aaaa")
    if resolver is not None:
        command.extend(("-r", resolver))
    if threads is not None:
        command.extend(("-t", str(threads)))
    if rate_limit is not None:
        command.extend(("-rl", str(rate_limit)))
    if query_timeout is not None:
        command.extend(("-timeout", f"{query_timeout:g}s"))
    if retry is not None:
        command.extend(("-retry", str(retry)))
    if auto_wildcard:
        command.append("-auto-wildcard")
    if json_output:
        command.append("-j")

    def parse_json_line(line: str) -> str | None:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return None

        if not isinstance(record, dict):
            return None

        host = record.get("host")
        if not isinstance(host, str) or clean_subdomain(host) not in candidates:
            return None
        if metadata is not None:
            metadata.append(record)
        return host

    try:
        result = run_passive_provider(
            domain="",
            provider_name="DNSx",
            command=command,
            telemetry_callback=telemetry_callback,
            timeout=timeout,
            input_text="\n".join(subdomains) + "\n",
            output_parser=(parse_json_line if json_output else
                           lambda line: line if clean_subdomain(line) in candidates else None),
        )
    except ProviderInterrupted as error:
        raise ProviderInterrupted(replace(error.result, metadata=metadata)) from error
    return replace(result, metadata=metadata)
