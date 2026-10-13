#!/usr/bin/env python3
"""Classify compatibility evidence and propose reviewed registry promotions."""

import argparse
import json
from pathlib import Path
import re


PLATFORMS = {"Linux", "Windows"}
AMD64_NAMES = {"amd64", "x86_64"}


def summarize(manifest: dict, checks: list[dict], regression: str) -> dict:
    results = []
    for candidate in manifest["matrix"]:
        provider, version = candidate["provider"], candidate["version"]
        evidence = [item for item in checks
                    if item.get("provider") == provider and item.get("expected_version") == version]
        platforms = {item.get("platform") for item in evidence}
        architectures = {str(item.get("architecture", "")).lower() for item in evidence}
        incompatible = any(item.get("classification") == "incompatible" for item in evidence)
        approved = (
            regression == "success"
            and platforms == PLATFORMS
            and architectures <= AMD64_NAMES
            and "" not in architectures
            and all(item.get("status") == "passed" and item.get("classification") == "approved"
                    for item in evidence)
        )
        classification = "approved" if approved else "incompatible" if incompatible else "limited"
        results.append({
            "provider": provider,
            "version": version,
            "classification": classification,
            "platforms": sorted(platforms - {None}),
            "architectures": sorted(architectures - {""}),
            "missing_platforms": sorted(PLATFORMS - platforms),
            "evidence": evidence,
        })
    return {
        "regression": regression,
        "evidence_complete": all(not item["missing_platforms"] for item in results),
        "results": results,
    }


def propose_promotions(report: dict, registry: dict) -> list[dict[str, str]]:
    proposals = []
    for result in report["results"]:
        if result["classification"] != "approved":
            continue
        provider, version = result["provider"], result["version"]
        spec = registry[provider]
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            continue
        if int(version.split(".")[0]) not in spec["supported_majors"]:
            continue
        if version not in spec["tested_versions"]:
            spec["tested_versions"].append(version)
            spec["tested_versions"].sort(key=lambda value: tuple(map(int, value.split("."))))
            proposals.append({"provider": provider, "version": version})
    return proposals


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--regression", required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    checks = [json.loads(path.read_text(encoding="utf-8"))
              for path in sorted(args.evidence.rglob("*.json"))]
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    report = summarize(manifest, checks, args.regression)
    report["registry_proposals"] = propose_promotions(report, registry)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["registry_proposals"]:
        args.registry.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
