"""Evaluate retained passive reports without network requests or provider execution."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


HEADER = re.compile(r"Source\s+Duration\s+Results\s+Requests\s+Errors")
STAT = re.compile(r"([a-z0-9_-]+)\s+[0-9.]+(?:ms|s|m|h)\s+(\d+)\s+(\d+)\s+(\d+)")
WARNING = re.compile(r"Encountered an error with source ([a-z0-9_-]+):\s*(.*)")
SELECTION = re.compile(r"Selected source\(s\) for this search:\s*(.*)")


def evaluate_provider(provider: dict, selected_sources: list[str] | None = None) -> dict:
    """Report request health separately from provider exit and finding count.

    Only the recognized Subfinder statistics format establishes request health.
    A warning alone cannot show whether a later fallback recovered.
    """
    sources = set(selected_sources or [])
    statistics, warnings = {}, {}
    in_table = False
    for raw in provider.get("diagnostics", []):
        for line in raw.splitlines():
            line = line.removeprefix("subfinder: ").strip()
            selection = SELECTION.search(line)
            if selection:
                sources.update(re.findall(r"[a-z0-9_-]+", selection[1]))
            warning = WARNING.search(line)
            if warning:
                sources.add(warning[1])
                warnings.setdefault(warning[1], []).append(warning[2])
            if HEADER.fullmatch(line):
                in_table = True
                continue
            stat = STAT.fullmatch(line) if in_table else None
            if stat:
                source, findings, requests, errors = stat.groups()
                sources.add(source)
                statistics[source] = {"findings": int(findings), "requests": int(requests), "errors": int(errors)}
    observations = []
    for source in sorted(sources):
        stats = statistics.get(source)
        health, reason = "unknown", "No recognized completed-request statistics"
        if stats and stats["requests"] > 0:
            if stats["errors"]:
                health = "request_errors"
                reason = "Source statistics record request errors"
            elif warnings.get(source):
                reason = "Zero-error statistics conflict with retained source warnings"
            else:
                health, reason = "healthy", "Source statistics record requests with zero errors"
        observations.append({"source": source, "health": health, "reason": reason,
                             "statistics": stats, "request_diagnostics": warnings.get(source, [])})
    states = {row["health"] for row in observations}
    health = ("unknown" if not states or "unknown" in states else
              "healthy" if states == {"healthy"} else
              "request_errors" if states == {"request_errors"} else "degraded")
    return {"provider": provider["name"], "process_status": provider.get("status", "unknown"),
            "exit_code": provider.get("exit_code"), "finding_count": len(provider.get("subdomains", [])),
            "source_health": health, "sources": observations,
            "coverage": "Unknown; source health and findings do not establish exhaustive discovery"}


def evaluate_document(document: dict, selected_sources: list[str] | None = None) -> dict:
    if document.get("schema", {}).get("name") != "hylianscan_passive_subdomain_discovery":
        raise ValueError("Expected a Hylianscan passive JSON report")
    return {"schema": {"name": "hylianscan_source_health_evaluation", "version": 1},
            "finding_count": len(document["results"]["subdomains"]),
            "providers": [evaluate_provider(provider, selected_sources if provider["name"] == "subfinder" else None)
                          for provider in document["providers"] if provider.get("role", "discovery") == "discovery"]}


def main(argv: list[str] | None = None) -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("report", type=Path, help="Existing passive JSON report")
    cli.add_argument("--source", action="append", help="Known selected Subfinder source; repeat as needed")
    cli.add_argument("--output", type=Path, help="New evaluation JSON file; existing files are preserved")
    args = cli.parse_args(argv)
    try:
        evaluation = evaluate_document(json.loads(args.report.read_text(encoding="utf-8")), args.source)
        text = json.dumps(evaluation, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(text)
        else:
            print(text, end="")
    except (OSError, ValueError, KeyError, TypeError) as error:
        cli.exit(1, f"Evaluation failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
