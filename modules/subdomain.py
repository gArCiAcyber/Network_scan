"""Passive subdomain discovery integration for hylianscan."""

import re
import os
import shutil
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TextIO


TelemetryCallback = Callable[[str], None]

ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
DEFAULT_PROVIDER_TIMEOUT_SECONDS = 180.0
PROVIDER_SHUTDOWN_GRACE_SECONDS = 5.0


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
) -> list[str]:
    """Run one passive discovery provider and return clean subdomain results."""
    subdomains: list[str] = []
    seen: set[str] = set()
    first_result_observed = False

    if telemetry_callback is not None:
        telemetry_callback(f"{provider_name} provider started")

    def handle_stdout(line: str) -> None:
        nonlocal first_result_observed

        subdomain = clean_subdomain(line)

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
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
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

    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        if telemetry_callback is not None:
            telemetry_callback(f"{provider_name} provider timeout")

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

    if return_code is not None and return_code != 0 and telemetry_callback is not None:
        telemetry_callback(f"[-] {provider_name} exited with status code {return_code}.")

    if return_code is not None and telemetry_callback is not None:
        telemetry_callback(f"{provider_name} provider completed")

    return sorted(subdomains)


def run_subfinder(
    domain: str,
    telemetry_callback: TelemetryCallback | None = None,
    timeout: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    executable_path: str | None = None,
) -> list[str]:
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
) -> list[str]:
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
