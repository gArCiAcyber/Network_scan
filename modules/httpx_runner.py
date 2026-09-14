"""Optional ProjectDiscovery HTTPx web-probing integration."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
from typing import Any


DEFAULT_HTTPX_BINARY = "httpx"
# ponytail: one batch timeout; add chunking/resume when large scopes require it.
DEFAULT_HTTPX_TIMEOUT = 300.0
MAX_SUMMARY_FINDINGS = 20
STDERR_PREVIEW_LIMIT = 500


@dataclass(frozen=True)
class HttpxResult:
    """Structured outcome from an optional HTTPx web probe."""

    status: str
    targets_requested: tuple[str, ...]
    findings: tuple[dict[str, Any], ...] = ()
    reason: str | None = None


def normalize_httpx_targets(targets: Sequence[str]) -> list[str]:
    """Validate, deduplicate, and sort HTTPx input targets."""
    if isinstance(targets, (str, bytes)):
        raise ValueError("HTTPx requires a sequence of target hosts.")

    normalized: set[str] = set()
    for target in targets:
        if not isinstance(target, str) or not target.strip():
            raise ValueError(f"Invalid HTTPx target: {target!r}.")
        normalized.add(target.strip().lower().strip("."))

    if not normalized:
        raise ValueError("HTTPx requires at least one target host.")

    return sorted(normalized)


def build_httpx_command(
    httpx_binary: str = DEFAULT_HTTPX_BINARY,
) -> list[str]:
    """Build the fixed HTTPx JSONL fingerprinting command."""
    clean_binary = httpx_binary.strip()
    if not clean_binary:
        raise ValueError("HTTPx requires a binary name or path.")

    return [
        clean_binary,
        "-silent",
        "-no-color",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
        "-ip",
        "-cname",
        "-location",
        "-no-fallback",
    ]


def parse_httpx_jsonl(output: str) -> tuple[dict[str, Any], ...]:
    """Parse HTTPx JSONL stdout into report-ready records."""
    findings: list[dict[str, Any]] = []

    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line.strip():
            continue

        try:
            finding = json.loads(line)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"HTTPx returned malformed JSONL on line {line_number}."
            ) from error

        if not isinstance(finding, dict):
            raise RuntimeError(
                f"HTTPx returned a non-object JSON value on line {line_number}."
            )

        findings.append(finding)

    return tuple(findings)


def run_httpx(
    targets: Sequence[str],
    *,
    httpx_binary: str = DEFAULT_HTTPX_BINARY,
    timeout: float = DEFAULT_HTTPX_TIMEOUT,
) -> HttpxResult:
    """Probe target hosts with HTTPx and parse JSONL stdout."""
    normalized_targets = normalize_httpx_targets(targets)
    command = build_httpx_command(httpx_binary)

    try:
        completed_process = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            input="\n".join(normalized_targets) + "\n",
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise RuntimeError(
            f"HTTPx binary not found: {command[0]}. Install HTTPx or provide "
            "a valid path with --httpx-path."
        ) from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"HTTPx timed out after {timeout:.1f} seconds.") from error
    except OSError as error:
        raise RuntimeError(f"Unable to start HTTPx: {error}") from error

    if completed_process.returncode != 0:
        stderr = " ".join((completed_process.stderr or "").split())
        stderr = stderr[:STDERR_PREVIEW_LIMIT].rstrip() or "no stderr output"
        raise RuntimeError(
            f"HTTPx failed with exit code {completed_process.returncode}: {stderr}"
        )

    return HttpxResult(
        status="completed",
        targets_requested=tuple(normalized_targets),
        findings=parse_httpx_jsonl(completed_process.stdout),
    )


def build_skipped_httpx_result(
    targets: Sequence[str],
    reason: str,
) -> HttpxResult:
    """Build a skipped HTTPx result without losing passive discoveries."""
    return HttpxResult(
        status="skipped",
        targets_requested=tuple(normalize_httpx_targets(targets)),
        reason=reason,
    )


def format_httpx_summary(
    result: HttpxResult,
    output_path: str | None = None,
) -> str:
    """Return a concise terminal summary for an HTTPx run."""
    lines = [
        "[+] HTTPX WEB PROBE",
        f"Status          : {result.status}",
        f"Targets probed  : {len(result.targets_requested)}",
        f"Live services   : {len(result.findings)}",
    ]

    if result.reason:
        lines.append(f"Reason          : {result.reason}")
    elif result.findings:
        lines.extend(["", f"{'CODE':<6} {'URL':<44} TITLE / TECHNOLOGIES"])
        for finding in result.findings[:MAX_SUMMARY_FINDINGS]:
            technologies = finding.get("tech") or []
            if isinstance(technologies, str):
                technologies = [technologies]
            details = " / ".join(
                value
                for value in (
                    str(finding.get("title") or "").strip(),
                    ", ".join(str(value) for value in technologies),
                )
                if value
            )
            lines.append(
                f"{str(finding.get('status_code') or '-'):<6} "
                f"{str(finding.get('url') or finding.get('input') or '-'):<44} "
                f"{details or '-'}"
            )
        if len(result.findings) > MAX_SUMMARY_FINDINGS:
            lines.append(
                f"... {len(result.findings) - MAX_SUMMARY_FINDINGS} more in JSONL output"
            )

    if output_path:
        lines.append(f"JSONL output    : {output_path}")

    lines.append("-" * 72)
    return "\n".join(lines)


def write_httpx_jsonl(result: HttpxResult, output_path: Path) -> None:
    """Persist successful HTTPx records as JSONL."""
    if result.status != "completed":
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "".join(
            json.dumps(finding, sort_keys=True) + "\n"
            for finding in result.findings
        ),
        encoding="utf-8",
    )
