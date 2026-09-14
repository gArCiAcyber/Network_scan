"""Passive subdomain discovery integration for hylianscan."""

import json
import re
import os
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from modules.target import normalize_address_family


TelemetryCallback = Callable[[str], None]

ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
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
    return ANSI_PATTERN.sub("", value).strip()


def clean_subdomain(value: str) -> str | None:
    """Normalize one provider stdout line into a subdomain candidate."""
    candidate = clean_terminal_text(value).lower().strip(".")

    if not candidate or "." not in candidate:
        return None

    if any(character.isspace() for character in candidate):
        return None

    return candidate


def stream_lines(stream: TextIO | None, line_handler: Callable[[str], None]) -> None:
    """Read a subprocess stream line by line and send clean text to a handler."""
    if stream is None:
        return

    for raw_line in stream:
        line = clean_terminal_text(raw_line)

        if line:
            line_handler(line)


def run_passive_provider(
    domain: str,
    provider_name: str,
    command: list[str],
    telemetry_callback: TelemetryCallback | None = None,
    timeout: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    input_text: str | None = None,
    output_parser: Callable[[str], str | None] | None = None,
) -> ProviderRunResult:
    """Run one passive provider and preserve results plus execution status."""
    subdomains: list[str] = []
    seen: set[str] = set()
    first_result_observed = False
    status = "completed"
    reason = None

    if telemetry_callback is not None:
        telemetry_callback(f"{provider_name} provider started")

    def handle_stdout(line: str) -> None:
        nonlocal first_result_observed

        parsed_line = output_parser(line) if output_parser is not None else line
        subdomain = clean_subdomain(parsed_line or "")

        if subdomain is None or subdomain in seen:
            return

        seen.add(subdomain)
        subdomains.append(subdomain)

        if telemetry_callback is not None and not first_result_observed:
            first_result_observed = True
            telemetry_callback(f"{provider_name} first result observed")

    def handle_stderr(line: str) -> None:
        if telemetry_callback is not None:
            telemetry_callback(line)

    try:
        popen_arguments = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "bufsize": 1,
        }

        if input_text is not None:
            popen_arguments["stdin"] = subprocess.PIPE

        process = subprocess.Popen(command, **popen_arguments)
    except FileNotFoundError as error:
        raise ValueError(
            build_provider_missing_message(provider_name, f"--{provider_name.lower()}-path")
        ) from error
    except OSError as error:
        raise ValueError(f"Unable to start {provider_name}: {error}") from error

    stdout_thread = threading.Thread(
        target=stream_lines,
        args=(process.stdout, handle_stdout),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=stream_lines,
        args=(process.stderr, handle_stderr),
        daemon=True,
    )

    stdout_thread.start()
    stderr_thread.start()

    if input_text is not None and process.stdin is not None:
        try:
            process.stdin.write(input_text)
            process.stdin.close()
        except BrokenPipeError:
            pass

    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        status = "timed_out"
        reason = f"Timed out after {timeout:g} seconds."
        warning = f"[-] {provider_name} timed out; returning partial results."
        if telemetry_callback is not None:
            telemetry_callback(warning)
        else:
            print(warning, file=sys.stderr)

        process.terminate()

        try:
            process.wait(timeout=PROVIDER_SHUTDOWN_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

        return_code = None
    except KeyboardInterrupt:
        process.terminate()
        raise
    finally:
        stdout_thread.join(timeout=PROVIDER_SHUTDOWN_GRACE_SECONDS)
        stderr_thread.join(timeout=PROVIDER_SHUTDOWN_GRACE_SECONDS)

        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()

    if return_code is not None and return_code != 0:
        status = "failed"
        reason = f"Exited with status code {return_code}."
        warning = (
            f"[-] Warning: {provider_name} exited with status code {return_code}; "
            "returning partial results."
        )
        if telemetry_callback is not None:
            telemetry_callback(warning)
        else:
            print(warning, file=sys.stderr)

    if return_code is not None and telemetry_callback is not None:
        telemetry_callback(f"{provider_name} provider completed")

    return ProviderRunResult(
        subdomains=sorted(subdomains),
        status=status,
        exit_code=return_code,
        reason=reason,
    )


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

    return run_passive_provider(
        domain=domain,
        provider_name="Amass",
        command=[executable, "enum", "-passive", "-d", domain],
        telemetry_callback=telemetry_callback,
        timeout=timeout,
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

        if metadata is not None:
            metadata.append(record)
        host = record.get("host")
        return host if isinstance(host, str) else None

    result = run_passive_provider(
        domain="",
        provider_name="DNSx",
        command=command,
        telemetry_callback=telemetry_callback,
        timeout=timeout,
        input_text="\n".join(subdomains) + "\n",
        output_parser=parse_json_line if json_output else None,
    )
    return ProviderRunResult(
        subdomains=result.subdomains,
        status=result.status,
        exit_code=result.exit_code,
        reason=result.reason,
        metadata=metadata,
    )
