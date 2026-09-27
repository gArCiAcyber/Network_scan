"""Local compatibility policy shared by runtime checks and maintenance scripts."""

import json
import re
from importlib.resources import files


PROVIDERS = json.loads(files("modules").joinpath("provider_compatibility.json").read_text(encoding="utf-8"))
VERSION_PATTERN = re.compile(r"(?<![\w.])v?(\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?)(?![\w.])")


def classify_version(provider: str, version: str) -> str:
    """Exact contract baselines are tested; other supported stable versions are untested."""
    spec = PROVIDERS[provider]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        return "unsupported"
    if int(version.split(".")[0]) not in spec["supported_majors"]:
        return "unsupported"
    return "tested" if version in spec["tested_versions"] else "untested"


def missing_flags(provider: str, help_output: str, required: list[str] | None = None) -> list[str]:
    """Match complete option tokens, so -aaaa cannot satisfy -a."""
    flags = set(re.findall(r"(?<![\w-])--?[a-zA-Z][\w-]*(?![\w-])", help_output))
    return sorted(set(required if required is not None else PROVIDERS[provider]["required_flags"]) - flags)
