#!/usr/bin/env python3
"""Smoke-check Hylianscan against a real DNSx executable."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path


DNSX_VERSION = "1.3.1"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(REPOSITORY_ROOT))

from modules.subdomain import run_dnsx


def main() -> int:
    """Validate the pinned DNSx version and Hylianscan stdin/stdout contract."""
    executable = shutil.which("dnsx")
    if executable is None:
        raise SystemExit("dnsx was not found on PATH")

    version = subprocess.run(
        [executable, "-version"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    version_output = version.stdout + version.stderr
    if version.returncode != 0:
        raise SystemExit(f"dnsx -version exited with {version.returncode}: {version_output}")
    if re.search(rf"\bv?{re.escape(DNSX_VERSION)}\b", version_output) is None:
        raise SystemExit(f"expected dnsx {DNSX_VERSION}, got: {version_output}")

    result = run_dnsx(
        ["example.com", "hylianscan-smoke.invalid"],
        executable_path=executable,
        timeout=30,
    )
    assert result.status == "completed", result
    assert result.exit_code == 0, result
    assert result.subdomains == ["example.com"], result

    print(f"DNSx {DNSX_VERSION} smoke check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
