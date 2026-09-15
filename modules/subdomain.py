"""Passive subdomain discovery integration for hylianscan."""

import json
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


TelemetryCallback = Callable[[str], None]

ANSI_PATTERN = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")
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

    def handle_line(line: str, stderr: bool) -> None:
        nonlocal next_diagnostic
        line = clean_terminal_text(line)
        if not line:
            return
        if stderr:
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
                    lines = (pending[index] + chunk).split(b"\n")
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
                    emit(f"{provider_name} progress: {now - started:.0f}s / {timeout:g}s; {len(seen)} candidates")
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
        emit(f"{provider_name} provider completed: exit 0; {len(seen)} candidates")
    if interrupted:
        raise ProviderInterrupted(result)
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
    version = re.search(r"\bv?(\d+)\.\d+\.\d+\b",
                        "\n".join([*version_lines, *version_result.diagnostics]))
    if version_result.status != "completed" or version is None:
        return ProviderRunResult([], "failed", reason="Unable to verify Amass version.",
                                 diagnostics=version_result.diagnostics)
    if version.group(1) not in {"3", "4"}:
        return ProviderRunResult(
            [], "failed", reason=(
                f"Amass {version.group(0)} is unsupported. Use Amass 3.x or 4.x "
                "with --amass-path; Amass 5 requires a separate engine/session integration."
            ),
        )
    remaining = timeout - (time.monotonic() - started)
    if remaining <= 0:
        return ProviderRunResult([], "timed_out", reason=f"Timed out after {timeout:g} seconds.")

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
    if not subdomains:
        if executable_path is not None:
            resolve_provider_executable(
                provider_name="DNSx",
                default_command="dnsx",
                path_option="--dnsx-path",
                explicit_path=executable_path,
            )
        return ProviderRunResult(
            subdomains=[],
            status="skipped",
            reason="No candidate subdomains to resolve.",
            metadata=metadata,
        )

    executable = resolve_provider_executable(
        provider_name="DNSx",
        default_command="dnsx",
        path_option="--dnsx-path",
        explicit_path=executable_path,
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
