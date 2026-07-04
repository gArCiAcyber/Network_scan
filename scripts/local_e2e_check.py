#!/usr/bin/env python3
"""Run local end-to-end Hylianscan CLI smoke checks."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
NMAP_XML_FIXTURE = Path("docs") / "examples" / "nmap_single_host.xml"

sys.path.insert(0, str(REPOSITORY_ROOT))

from core.version import APP_NAME, APP_VERSION


@dataclass(frozen=True)
class SmokeCheck:
    """One local CLI command and its expected output snippets."""

    name: str
    command: tuple[str, ...]
    expected_snippets: tuple[str, ...]


def build_checks() -> tuple[SmokeCheck, ...]:
    """Return safe local CLI flows that do not require external tools."""
    python = sys.executable

    return (
        SmokeCheck(
            name="Version command",
            command=(python, "hylianscan.py", "--version"),
            expected_snippets=(f"{APP_NAME} {APP_VERSION}",),
        ),
        SmokeCheck(
            name="Help command",
            command=(python, "hylianscan.py", "--help"),
            expected_snippets=("usage: hylianscan", "--nmap-xml"),
        ),
        SmokeCheck(
            name="Scan stances listing",
            command=(python, "hylianscan.py", "--list-stances"),
            expected_snippets=("Built-in TCP scan stances:", "balanced / nayru"),
        ),
        SmokeCheck(
            name="Port profiles listing",
            command=(python, "hylianscan.py", "--list-port-profiles"),
            expected_snippets=("Built-in TCP port profiles:", "bugbounty / triforce"),
        ),
        SmokeCheck(
            name="Nmap XML import fixture",
            command=(python, "hylianscan.py", "--nmap-xml", str(NMAP_XML_FIXTURE)),
            expected_snippets=("Nmap XML Import", "Open TCP Ports: 2"),
        ),
    )


def format_command(command: tuple[str, ...]) -> str:
    """Return a readable command string for local logs."""
    return " ".join(command)


def require_fixture() -> None:
    """Stop early when the committed Nmap XML fixture is missing."""
    fixture_path = REPOSITORY_ROOT / NMAP_XML_FIXTURE

    if not fixture_path.is_file():
        print(f"[FAIL] Missing Nmap XML fixture: {NMAP_XML_FIXTURE}")
        raise SystemExit(1)


def run_check(check: SmokeCheck) -> None:
    """Run one smoke check and validate stable output snippets."""
    print(f"\n==> {check.name}")
    print(f"$ {format_command(check.command)}")

    completed = subprocess.run(
        check.command,
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        shell=False,
    )
    output = completed.stdout + completed.stderr

    if completed.returncode != 0:
        print(output, end="")
        print(f"[FAIL] {check.name}: exit code {completed.returncode}")
        raise SystemExit(completed.returncode)

    missing_snippets = [
        snippet for snippet in check.expected_snippets if snippet not in output
    ]

    if missing_snippets:
        print(output, end="")
        print(f"[FAIL] {check.name}: missing expected output snippets:")
        for snippet in missing_snippets:
            print(f"  - {snippet}")
        raise SystemExit(1)

    print(f"[PASS] {check.name}")


def main() -> int:
    """Execute all local end-to-end smoke checks."""
    require_fixture()
    checks = build_checks()

    print("Hylianscan local E2E smoke check")
    print(f"Repository root: {REPOSITORY_ROOT}")

    for check in checks:
        run_check(check)

    print(f"\nPASS: {len(checks)} local E2E smoke checks completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
