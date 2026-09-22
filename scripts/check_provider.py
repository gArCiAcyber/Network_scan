#!/usr/bin/env python3
"""Check a real provider's version/CLI contract and persist CI evidence."""

import argparse
import json
from pathlib import Path
import platform
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules.provider_compatibility import PROVIDERS
from modules.subdomain import (
    ProviderRunResult, inspect_provider_compatibility, run_amass, run_passive_provider,
)
from scripts.check_dnsx import check_dnsx


class LimitedEvidence(Exception):
    def __init__(self, message: str, evidence: dict):
        super().__init__(message)
        self.evidence = evidence


def provider_evidence(arguments: list[str], result: ProviderRunResult) -> dict:
    return {
        "arguments": arguments,
        "status": result.status,
        "exit_code": result.exit_code,
        "subdomains": result.subdomains,
        "diagnostics": list(result.diagnostics),
        "elapsed_seconds": result.elapsed_seconds,
    }


def check_subfinder(executable: Path) -> dict:
    """Exercise a reserved target; parser/report semantics stay fixture-driven."""
    normal_arguments = ["-d", "example.test", "-silent"]
    normal = run_passive_provider(
        "example.test", "Subfinder normal-output check",
        [str(executable), *normal_arguments], timeout=75,
    )
    evidence = {"normal_output": provider_evidence(normal_arguments, normal)}
    if normal.status == "timed_out" or not normal.subdomains:
        raise LimitedEvidence(
            normal.reason or "Reserved-domain run produced no normal output.",
            {"subfinder": evidence},
        )
    if normal.status != "completed":
        raise ValueError(f"Reserved-domain normal-output check {normal.status}: {normal.reason}")

    empty_arguments = ["-d", "hylianscan-empty.invalid", "-silent"]
    empty = run_passive_provider(
        "hylianscan-empty.invalid", "Subfinder empty-output check",
        [str(executable), *empty_arguments], timeout=75,
    )
    evidence["empty_output"] = provider_evidence(empty_arguments, empty)
    if empty.status == "timed_out":
        raise LimitedEvidence(empty.reason or "Empty-output check timed out.", {"subfinder": evidence})
    if empty.status != "completed" or empty.subdomains:
        raise ValueError(f"Reserved empty-output check was unexpected: {empty.status}.")

    error_arguments = ["--hylianscan-unknown"]
    error = run_passive_provider(
        "", "Subfinder unknown-option check", [str(executable), *error_arguments], timeout=5,
    )
    evidence["unknown_option"] = provider_evidence(error_arguments, error)
    if error.status == "timed_out":
        raise LimitedEvidence(error.reason or "Unknown-option check timed out.", {"subfinder": evidence})
    if error.status == "completed":
        raise ValueError("Unknown option unexpectedly returned exit code 0.")
    return evidence


def check_amass(executable: Path) -> dict:
    evidence = {}
    for label, target, expect_output in (
        ("normal_output", "example.test", True),
        ("empty_output", "hylianscan-empty.invalid", False),
    ):
        result = run_amass(target, executable_path=str(executable), timeout=75)
        evidence[label] = provider_evidence(
            ["enum", "-passive", "-d", target], result,
        )
        if result.status == "timed_out" or (expect_output and not result.subdomains):
            raise LimitedEvidence(
                result.reason or "Reserved-domain run produced no normal output.",
                {"amass": evidence},
            )
        if result.status != "completed" or bool(result.subdomains) != expect_output:
            raise ValueError(f"Amass {label} check was unexpected: {result.status}.")
    return evidence


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
            result["checks"].extend([
                "reserved-domain execution", "empty/normal scoped output", "nonzero option error",
                "captured fixture parsing, duplicates, timeout, TXT/JSON",
            ])
        if args.provider == "dnsx":
            result["dnsx"] = check_dnsx(str(args.executable.resolve()))
            result["checks"].append("localhost DNS: A/AAAA, JSON, NXDOMAIN, empty input")
        if args.provider == "amass":
            result["amass"] = check_amass(args.executable.resolve())
            result["checks"].append("captured graph/hostname parsing, errors, timeout, TXT/JSON")
        result.update(status="passed", classification="approved")
    except LimitedEvidence as error:
        failure = error
        result.update(error.evidence)
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
