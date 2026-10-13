#!/usr/bin/env python3
"""Check a real provider's version/CLI contract and persist CI evidence."""

import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import platform
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules.provider_compatibility import PROVIDERS
from modules.subdomain import (
    ProviderRunResult, inspect_provider_compatibility, run_amass, run_passive_provider,
)
from scripts.check_dnsx import check_dnsx


class LimitedEvidence(Exception):
    """The available evidence cannot establish compatibility."""


def provider_evidence(arguments: list[str], result: ProviderRunResult) -> dict:
    return {
        "arguments": arguments,
        "status": result.status,
        "exit_code": result.exit_code,
        "subdomains": result.subdomains,
        "diagnostics": list(result.diagnostics),
        "elapsed_seconds": result.elapsed_seconds,
        "reason": result.reason,
    }


def check_subfinder(executable: Path) -> dict:
    """Exercise a reserved target; parser/report semantics stay fixture-driven."""
    normal_arguments = ["-d", "example.test", "-silent"]
    normal = run_passive_provider(
        "example.test", "Subfinder normal-output check",
        [str(executable), *normal_arguments], timeout=75,
    )
    evidence = {"normal_output": provider_evidence(normal_arguments, normal)}
    empty_arguments = ["-d", "hylianscan-empty.invalid", "-silent"]
    empty = run_passive_provider(
        "hylianscan-empty.invalid", "Subfinder empty-output check",
        [str(executable), *empty_arguments], timeout=75,
    )
    evidence["empty_output"] = provider_evidence(empty_arguments, empty)
    error_arguments = ["--hylianscan-unknown"]
    error = run_passive_provider(
        "", "Subfinder unknown-option check", [str(executable), *error_arguments], timeout=5,
    )
    evidence["unknown_option"] = provider_evidence(error_arguments, error)
    return evidence


def check_amass(executable: Path) -> dict:
    evidence = {}
    for label, target in (
        ("normal_output", "example.test"),
        ("empty_output", "hylianscan-empty.invalid"),
    ):
        result = run_amass(target, executable_path=str(executable), timeout=75)
        evidence[label] = provider_evidence(
            ["enum", "-passive", "-d", target], result,
        )
    return evidence


def validate_execution(evidence: dict) -> None:
    """Judge exit behavior after every check has run, independently of findings."""
    failed = []
    incomplete = []
    for name, check in evidence.items():
        if check["status"] in {"timed_out", "interrupted", "skipped"}:
            incomplete.append(name)
        elif name == "unknown_option":
            if check["status"] != "failed" or check["exit_code"] in (None, 0):
                failed.append(name)
        elif check["status"] != "completed" or check["exit_code"] != 0:
            failed.append(name)
    if failed:
        raise ValueError(f"Unexpected provider exit behavior: {', '.join(failed)}")
    if incomplete:
        raise LimitedEvidence(f"Provider execution did not complete: {', '.join(incomplete)}")


def check_fixture_contract(provider: str) -> dict:
    """Run the existing offline parser/report regressions and record actual results."""
    modules = ["tests.test_json_exporter"]
    modules.append("tests.test_subfinder_release_compatibility" if provider == "subfinder"
                   else "tests.test_subdomain")
    output = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
    with redirect_stdout(output), redirect_stderr(output):
        result = unittest.TextTestRunner(stream=output).run(suite)
    return {
        "status": "passed" if result.wasSuccessful() else "failed",
        "modules": modules,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "output": output.getvalue(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", choices=PROVIDERS)
    parser.add_argument("version")
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"provider": args.provider, "expected_version": args.version,
              "platform": platform.system(), "architecture": platform.machine(),
              "status": "failed", "classification": "limited", "checks": []}
    failure = None
    try:
        result["fixtures"] = check_fixture_contract(args.provider)
        if result["fixtures"]["status"] == "passed":
            result["checks"].append("offline fixture parsing and reports")
        checked = inspect_provider_compatibility(args.provider, str(args.executable.resolve()))
        result.update(version=checked["version"], compatibility=checked["status"])
        if checked["version"] != args.version:
            raise ValueError(f"Expected {args.version}, got {checked['version']}")
        if checked["status"] in {"unsupported", "unverified", "incompatible"}:
            raise ValueError(checked.get("reason", f"Compatibility is {checked['status']}"))
        spec = PROVIDERS[args.provider]
        result["required_flags"] = (spec["required_flags_v5"] if args.provider == "amass"
                                    and args.version.startswith("5.") else spec["required_flags"])
        result["checks"].extend(["version", "required CLI options"])
        if args.provider == "subfinder":
            result["subfinder"] = check_subfinder(args.executable.resolve())
        if args.provider == "dnsx":
            result["dnsx"] = check_dnsx(str(args.executable.resolve()))
            result["checks"].append("localhost DNS: A/AAAA, JSON, NXDOMAIN, empty input")
        if args.provider == "amass":
            result["amass"] = check_amass(args.executable.resolve())
        if args.provider in {"subfinder", "amass"}:
            evidence = result[args.provider]
            discovery = evidence["normal_output"]
            result["source_availability"] = {
                "status": ("observed" if discovery["subdomains"] else
                           "not_observed" if discovery["status"] == "completed" else "unknown"),
                "candidate_count": len(discovery["subdomains"]),
                "required_for_approval": False,
            }
            validate_execution(evidence)
            result["checks"].append("reserved-domain execution and exit behavior")
        if result["fixtures"]["status"] != "passed":
            raise LimitedEvidence("Offline fixture regressions failed.")
        result.update(status="passed", classification="approved")
    except LimitedEvidence as error:
        failure = error
        result["error"] = str(error)
    except Exception as error:
        failure = error
        result["classification"] = "incompatible"
        result["error"] = str(error)
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
    if failure is not None:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
