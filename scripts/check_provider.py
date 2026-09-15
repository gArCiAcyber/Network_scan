#!/usr/bin/env python3
"""Check a real provider's version/CLI contract and persist CI evidence."""

import argparse
import json
from pathlib import Path
import platform
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules.provider_compatibility import PROVIDERS
from modules.subdomain import inspect_provider_compatibility
from scripts.check_dnsx import check_dnsx


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", choices=PROVIDERS)
    parser.add_argument("version")
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"provider": args.provider, "expected_version": args.version,
              "platform": platform.system(), "status": "failed"}
    try:
        checked = inspect_provider_compatibility(args.provider, str(args.executable.resolve()))
        if checked["version"] != args.version:
            raise ValueError(f"Expected {args.version}, got {checked['version']}")
        result.update(version=checked["version"], compatibility=checked["status"])
        result["checks"] = ["version", "required CLI options"]
        if args.provider == "dnsx":
            check_dnsx(str(args.executable.resolve()))
            result["checks"].append("localhost DNS: A/AAAA, JSON, NXDOMAIN, empty input")
        result["status"] = "passed"
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
