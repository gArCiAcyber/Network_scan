#!/usr/bin/env python3
"""Smoke-check a real DNSx binary against controlled localhost DNS responses."""

from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules.provider_compatibility import PROVIDERS
from modules.subdomain import inspect_provider_compatibility, run_dnsx
from tests.fixtures.dns_server import local_dns


def check_dnsx(executable: str) -> dict:
    evidence = {}
    with local_dns() as resolver:
        for family in ("ipv4", "ipv6", "dual-stack"):
            result = run_dnsx(
                ["live.example.test", "dead.example.test"], executable_path=executable,
                resolver=resolver, address_family=family, threads=2, rate_limit=20,
                query_timeout=1, retry=1, json_output=True, timeout=15,
            )
            assert result.status == "completed", result
            assert result.subdomains == ["live.example.test"], result
            assert result.metadata and result.metadata[0]["host"] == "live.example.test", result
            evidence[family] = {
                "status": result.status,
                "exit_code": result.exit_code,
                "subdomains": result.subdomains,
                "metadata": result.metadata,
                "elapsed_seconds": result.elapsed_seconds,
            }
        empty = run_dnsx([], executable_path=executable)
        assert empty.status == "skipped", empty
        evidence["empty_input"] = {"status": empty.status, "reason": empty.reason}
    return evidence


def main() -> int:
    executable = shutil.which("dnsx")
    if executable is None:
        raise SystemExit("dnsx was not found on PATH")
    checked = inspect_provider_compatibility("dnsx", executable)
    assert checked["version"] == PROVIDERS["dnsx"]["baseline"], checked
    check_dnsx(executable)
    print(f"DNSx {checked['version']} localhost smoke check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
