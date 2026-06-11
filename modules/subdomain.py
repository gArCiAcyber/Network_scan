"""Passive subdomain discovery integration for hylianscan."""

import re
import subprocess
import threading
from collections.abc import Callable
from typing import TextIO


TelemetryCallback = Callable[[str], None]

ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
DEFAULT_PROVIDER_TIMEOUT_SECONDS = 180.0
PROVIDER_SHUTDOWN_GRACE_SECONDS = 5.0


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

    def handle_stdout(line: str) -> None:
        subdomain = clean_subdomain(line)

        if subdomain is None or subdomain in seen:
            return

        seen.add(subdomain)
        subdomains.append(subdomain)

        if telemetry_callback is not None:
            telemetry_callback(f"{provider_name} discovered subdomain")

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
    except OSError as error:
        if telemetry_callback is not None:
            telemetry_callback(f"[-] Unable to start {provider_name}: {error}")
        return []

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
            telemetry_callback(f"{provider_name} timed out; preserving partial results")

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

    return sorted(subdomains)


def run_subfinder(
    domain: str,
    telemetry_callback: TelemetryCallback | None = None,
    timeout: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
) -> list[str]:
    """Run Subfinder passive discovery and return clean subdomain results."""
    return run_passive_provider(
        domain=domain,
        provider_name="Subfinder",
        command=["subfinder", "-d", domain, "-silent"],
        telemetry_callback=telemetry_callback,
        timeout=timeout,
    )


def run_amass(
    domain: str,
    telemetry_callback: TelemetryCallback | None = None,
    timeout: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
) -> list[str]:
    """Run Amass passive discovery and return clean subdomain results."""
    return run_passive_provider(
        domain=domain,
        provider_name="Amass",
        command=["amass", "enum", "-passive", "-d", domain],
        telemetry_callback=telemetry_callback,
        timeout=timeout,
    )
