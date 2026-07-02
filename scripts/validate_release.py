#!/usr/bin/env python3
"""Run Hylianscan release validation checks."""

from __future__ import annotations

import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
NMAP_XML_FIXTURE = Path("docs") / "examples" / "nmap_single_host.xml"
NMAP_IMPORT_TXT_OUTPUT = Path("output") / "nmap_import_report.txt"
NMAP_IMPORT_JSON_OUTPUT = Path("output") / "nmap_import_results.json"


def format_command(command: list[str]) -> str:
    """Return a shell-readable command string for logs."""
    return " ".join(shlex.quote(part) for part in command)


def print_step(title: str) -> None:
    """Print a clear validation step header."""
    print(f"\n==> {title}", flush=True)


def run_step(
    title: str,
    command: list[str],
    cwd: Path = REPOSITORY_ROOT,
) -> None:
    """Run one validation command and stop immediately on failure."""
    print_step(title)
    print(f"$ {format_command(command)}", flush=True)

    try:
        subprocess.run(
            command,
            cwd=cwd,
            check=True,
            stderr=subprocess.STDOUT,
        )
    except FileNotFoundError as error:
        print(f"\n[FAIL] Command not found: {command[0]}", file=sys.stderr)
        raise SystemExit(1) from error
    except subprocess.CalledProcessError as error:
        print(f"\n[FAIL] Command failed: {format_command(command)}", file=sys.stderr)
        raise SystemExit(error.returncode) from error


def require_file(path: Path, description: str) -> None:
    """Stop validation when a required release artifact is missing."""
    absolute_path = REPOSITORY_ROOT / path

    if not absolute_path.is_file():
        print(f"\n[FAIL] Missing {description}: {path}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    """Execute the release validation workflow."""
    python = sys.executable

    cleanup_nmap_import_outputs()

    run_step("Version command", [python, "hylianscan.py", "--version"])
    run_step("Help command", [python, "hylianscan.py", "--help"])
    validate_nmap_xml_fixture(python)
    validate_runtime_output_root(python)
    run_step(
        "Compile validation",
        [python, "-m", "compileall", "-q", "hylianscan.py", "core", "modules", "tests"],
    )
    run_step(
        "Unit test validation",
        [python, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"],
    )
    run_step("Package metadata dry run", [python, "-m", "pip", "install", "--dry-run", "."])
    cleanup_generated_metadata()

    if shutil.which("git"):
        run_step("Git whitespace validation", ["git", "diff", "--check"])
    else:
        print_step("Git whitespace validation")
        print("git was not found on PATH; skipping git diff --check.", flush=True)

    print_step("Release validation completed successfully")
    return 0


def validate_nmap_xml_fixture(python: str) -> None:
    """Validate the committed Nmap XML fixture and import report outputs."""
    require_file(NMAP_XML_FIXTURE, "Nmap XML fixture")

    run_step(
        "Nmap XML fixture import",
        [python, "hylianscan.py", "--nmap-xml", str(NMAP_XML_FIXTURE)],
    )
    try:
        run_step(
            "Nmap XML fixture TXT/JSON output",
            [
                python,
                "hylianscan.py",
                "--nmap-xml",
                str(NMAP_XML_FIXTURE),
                "-o",
                "nmap_import_report.txt",
                "--json-output",
                "nmap_import_results.json",
            ],
        )
        run_step(
            "Nmap XML JSON validation",
            [python, "-m", "json.tool", str(NMAP_IMPORT_JSON_OUTPUT)],
        )
    finally:
        cleanup_nmap_import_outputs()


def validate_runtime_output_root(python: str) -> None:
    """Validate default reports resolve under the runtime current directory."""
    require_file(NMAP_XML_FIXTURE, "Nmap XML fixture")
    cleanup_nmap_import_outputs()

    with tempfile.TemporaryDirectory(prefix="hylianscan-output-root-") as temporary_dir:
        runtime_cwd = Path(temporary_dir)
        expected_txt = runtime_cwd / NMAP_IMPORT_TXT_OUTPUT
        expected_json = runtime_cwd / NMAP_IMPORT_JSON_OUTPUT

        run_step(
            "Runtime CWD output root validation",
            [
                python,
                str(REPOSITORY_ROOT / "hylianscan.py"),
                "--nmap-xml",
                str(REPOSITORY_ROOT / NMAP_XML_FIXTURE),
                "-o",
                "--json-output",
            ],
            cwd=runtime_cwd,
        )

        for output_path in (expected_txt, expected_json):
            if not output_path.is_file():
                print(
                    f"\n[FAIL] Expected runtime output was not created: {output_path}",
                    file=sys.stderr,
                )
                raise SystemExit(1)

        for repository_output in (NMAP_IMPORT_TXT_OUTPUT, NMAP_IMPORT_JSON_OUTPUT):
            if (REPOSITORY_ROOT / repository_output).exists():
                print(
                    "\n[FAIL] Runtime output was written under the repository root "
                    f"instead of the runtime cwd: {repository_output}",
                    file=sys.stderr,
                )
                raise SystemExit(1)

        run_step(
            "Runtime CWD JSON validation",
            [python, "-m", "json.tool", str(expected_json)],
        )


def cleanup_nmap_import_outputs() -> None:
    """Remove release validation outputs generated by Nmap XML smoke checks."""
    for path in (NMAP_IMPORT_TXT_OUTPUT, NMAP_IMPORT_JSON_OUTPUT):
        absolute_path = REPOSITORY_ROOT / path
        absolute_path.unlink(missing_ok=True)


def cleanup_generated_metadata() -> None:
    """Remove package metadata generated by pip dry-run."""
    metadata_path = REPOSITORY_ROOT / "hylianscan.egg-info"

    if metadata_path.exists():
        shutil.rmtree(metadata_path)


if __name__ == "__main__":
    raise SystemExit(main())
