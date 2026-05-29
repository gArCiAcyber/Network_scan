"""Passive subdomain discovery integration for hylianscan."""

import re
import subprocess
import threading
from collections.abc import Callable
from typing import TextIO


TelemetryCallback = Callable[[str], None]

ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def clean_terminal_text(value: str) -> str:
    """Remove ANSI escape codes and surrounding whitespace from tool output."""
    return ANSI_PATTERN.sub("", value).strip()


def clean_subdomain(value: str) -> str | None:
    """Normalize one Subfinder stdout line into a subdomain candidate."""
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


def run_subfinder(
    domain: str,
    telemetry_callback: TelemetryCallback | None = None,
) -> list[str]:
    """Run Subfinder passive discovery and return clean subdomain results."""
    subdomains: list[str] = []
    seen: set[str] = set()

    def handle_stdout(line: str) -> None:
        subdomain = clean_subdomain(line)

        if subdomain is None or subdomain in seen:
            return

        seen.add(subdomain)
        subdomains.append(subdomain)

    def handle_stderr(line: str) -> None:
        if telemetry_callback is not None:
            telemetry_callback(line)

    try:
        process = subprocess.Popen(
            ["subfinder", "-d", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except OSError as error:
        if telemetry_callback is not None:
            telemetry_callback(f"[-] Unable to start Subfinder: {error}")
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
        return_code = process.wait()
    except KeyboardInterrupt:
        process.terminate()
        raise
    finally:
        stdout_thread.join()
        stderr_thread.join()

    if return_code != 0 and telemetry_callback is not None:
        telemetry_callback(f"[-] Subfinder exited with status code {return_code}.")

    return sorted(subdomains)
