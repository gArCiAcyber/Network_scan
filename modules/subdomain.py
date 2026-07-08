"""Passive subdomain discovery integration for hylianscan."""

import json
import os
import re
import shutil
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from typing import TextIO


TelemetryCallback = Callable[[str], None]

ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
DEFAULT_PROVIDER_TIMEOUT_SECONDS = 180.0
PROVIDER_SHUTDOWN_GRACE_SECONDS = 5.0


@dataclass
class PassiveProviderResult:
    """Structured result returned by one passive discovery provider."""

    provider: str
    candidates: list[str]
    observed_sources: list[str] = field(default_factory=list)
    candidate_sources: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    timed_out: bool = False
    exit_code: int | None = 0
    status: str = "completed"


@dataclass(frozen=True)
class ParsedProviderLine:
    """One parsed provider stdout line."""

    subdomain: str
    sources: tuple[str, ...] = ()


ProviderLineParser = Callable[[str], ParsedProviderLine | None]


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


def clean_source_name(value: Any) -> str | None:
    """Normalize one provider source name without inventing attribution."""
    if not isinstance(value, str):
        return None

    source = clean_terminal_text(value).strip().lower()
    return source or None


def normalize_source_values(value: Any) -> tuple[str, ...]:
    """Normalize provider source values from JSON string/list fields."""
    if isinstance(value, str):
        values: list[Any] = [part.strip() for part in value.split(",")]
    elif isinstance(value, list):
        values = value
    else:
        return ()

    sources = {
        source
        for source in (clean_source_name(item) for item in values)
        if source is not None
    }
    return tuple(sorted(sources))


def parse_plain_provider_line(line: str) -> ParsedProviderLine | None:
    """Parse one plain provider stdout line as a subdomain candidate."""
    subdomain = clean_subdomain(line)

    if subdomain is None:
        return None

    return ParsedProviderLine(subdomain=subdomain)


def parse_subfinder_json_line(line: str) -> ParsedProviderLine | None:
    """Parse one Subfinder JSONL line with optional source attribution."""
    try:
        payload = json.loads(clean_terminal_text(line))
    except json.JSONDecodeError:
        return parse_plain_provider_line(line)

    if not isinstance(payload, dict):
        return None

    host = (
        payload.get("host")
        or payload.get("subdomain")
        or payload.get("domain")
        or payload.get("name")
    )
    subdomain = clean_subdomain(str(host)) if host is not None else None

    if subdomain is None:
        return None

    sources = normalize_source_values(payload.get("sources"))

    if not sources:
        sources = normalize_source_values(payload.get("source"))

    return ParsedProviderLine(subdomain=subdomain, sources=sources)


def classify_provider_message(line: str) -> str:
    """Classify provider stderr text as a warning or an error."""
    lowered = line.lower()

    if (
        "error" in lowered
        or "failed" in lowered
        or "invalid" in lowered
        or "unknown" in lowered
        or line.startswith("[-]")
    ):
        return "error"

    return "warning"


def append_unique(values: list[str], value: str) -> None:
    """Append one value if it has not already been recorded."""
    if value not in values:
        values.append(value)


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
    stdout_parser: ProviderLineParser = parse_plain_provider_line,
) -> PassiveProviderResult:
    """Run one passive discovery provider and return structured results."""
    subdomains: list[str] = []
    seen: set[str] = set()
    observed_sources: set[str] = set()
    candidate_sources: dict[str, list[str]] = {}
    warnings: list[str] = []
    errors: list[str] = []
    timed_out = False
    line_parser = stdout_parser

    if telemetry_callback is not None:
        telemetry_callback(f"{provider_name} provider started")

    def handle_stdout(line: str) -> None:
        parsed_line = line_parser(line)

        if parsed_line is None:
            return

        observed_sources.update(parsed_line.sources)

        if parsed_line.sources:
            merged_sources = {
                *candidate_sources.get(parsed_line.subdomain, []),
                *parsed_line.sources,
            }
            candidate_sources[parsed_line.subdomain] = sorted(merged_sources)

        if parsed_line.subdomain in seen:
            return

        seen.add(parsed_line.subdomain)
        subdomains.append(parsed_line.subdomain)

    def handle_stderr(line: str) -> None:
        if classify_provider_message(line) == "error":
            append_unique(errors, line)
        else:
            append_unique(warnings, line)

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
        timed_out = True

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

    status = "completed"

    if timed_out:
        status = "timeout"
        append_unique(errors, f"{provider_name} timed out after {timeout:g} seconds.")
    elif return_code is not None and return_code != 0:
        status = "failed"
        append_unique(errors, f"{provider_name} exited with status code {return_code}.")

        if telemetry_callback is not None:
            telemetry_callback(f"[-] {provider_name} exited with status code {return_code}.")

    if return_code is not None and telemetry_callback is not None:
        telemetry_callback(f"{provider_name} provider completed")

    normalized_subdomains = sorted(subdomains)
    normalized_candidate_sources = {
        subdomain: sorted(set(candidate_sources.get(subdomain, [])))
        for subdomain in normalized_subdomains
        if candidate_sources.get(subdomain)
    }

    return PassiveProviderResult(
        provider=provider_name.lower(),
        candidates=normalized_subdomains,
        observed_sources=sorted(observed_sources),
        candidate_sources=normalized_candidate_sources,
        warnings=warnings,
        errors=errors,
        timed_out=timed_out,
        exit_code=return_code,
        status=status,
    )


def run_subfinder(
    domain: str,
    telemetry_callback: TelemetryCallback | None = None,
    timeout: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    executable_path: str | None = None,
) -> PassiveProviderResult:
    """Run Subfinder passive discovery and return structured results."""
    executable = resolve_provider_executable(
        provider_name="Subfinder",
        default_command="subfinder",
        path_option="--subfinder-path",
        explicit_path=executable_path,
    )

    json_result = run_passive_provider(
        domain=domain,
        provider_name="Subfinder",
        command=[executable, "-d", domain, "-silent", "-oJ", "-cs"],
        telemetry_callback=telemetry_callback,
        timeout=timeout,
        stdout_parser=parse_subfinder_json_line,
    )

    if json_result.status in {"completed", "timeout"} or json_result.candidates:
        return json_result

    plain_result = run_passive_provider(
        domain=domain,
        provider_name="Subfinder",
        command=[executable, "-d", domain, "-silent"],
        telemetry_callback=telemetry_callback,
        timeout=timeout,
        stdout_parser=parse_plain_provider_line,
    )

    merged_warnings = [
        *json_result.warnings,
        *[f"Subfinder JSON source mode fallback: {error}" for error in json_result.errors],
        *plain_result.warnings,
    ]
    plain_result.warnings = list(dict.fromkeys(merged_warnings))
    return plain_result


def run_amass(
    domain: str,
    telemetry_callback: TelemetryCallback | None = None,
    timeout: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    executable_path: str | None = None,
) -> PassiveProviderResult:
    """Run Amass passive discovery and return structured results."""
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
        stdout_parser=parse_plain_provider_line,
    )
