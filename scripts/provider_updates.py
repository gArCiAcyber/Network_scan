#!/usr/bin/env python3
"""Explicit maintenance commands; never imported by the scan startup path."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import sys
import tarfile
from urllib.request import Request, urlopen
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules.provider_compatibility import PROVIDERS, classify_version


def github_json(repository: str, endpoint: str) -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "Hylianscan-compatibility"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    request = Request(f"https://api.github.com/repos/{repository}/releases/{endpoint}", headers=headers)
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def stable_version(tag: str) -> str:
    if not re.fullmatch(r"v?\d+\.\d+\.\d+", tag):
        raise ValueError(f"Unsupported release tag: {tag!r}")
    return tag.removeprefix("v")


def collect_updates(provider: str | None = None, version: str | None = None) -> tuple[dict, list]:
    """Collect all releases before writing anything; API failures cannot promote versions."""
    if bool(provider) != bool(version):
        raise ValueError("Historical provider and version must be supplied together.")
    if provider is not None and provider not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}")
    if version is not None:
        version = stable_version(version)
    updates, matrix = {}, []
    for name, spec in PROVIDERS.items():
        release = github_json(spec["repository"], "latest")
        if release.get("draft") or release.get("prerelease"):
            raise ValueError(f"Expected a stable release for {name}")
        latest = stable_version(release["tag_name"])
        status = classify_version(name, latest)
        updates[name] = {
            "baseline": spec["baseline"], "latest": latest, "status": status,
            "release": f"https://github.com/{spec['repository']}/releases/tag/{release['tag_name']}",
        }
        versions = [spec["baseline"], latest]
        matrix.extend({"provider": name, "version": candidate} for candidate in dict.fromkeys(versions))
    if provider is not None and version is not None:
        historical = {"provider": provider, "version": version}
        if historical not in matrix:
            matrix.append(historical)
        updates[provider]["requested"] = version
    return updates, matrix


def install_release(provider: str, version: str, destination: Path) -> Path:
    """Install one official release in an isolated CI directory, never system PATH."""
    version = stable_version(version)
    system = platform.system().lower()
    if system not in {"windows", "linux"} or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise ValueError("Release smoke checks currently require Linux/Windows amd64.")
    release = github_json(PROVIDERS[provider]["repository"], f"tags/v{version}")
    assets = [asset for asset in release["assets"]
              if f"{system}_amd64" in asset["name"].lower()
              and asset["name"].lower().endswith((".zip", ".tar.gz"))]
    if len(assets) != 1:
        raise ValueError(f"Expected one {system}/amd64 archive for {provider} {version}")
    asset = assets[0]
    url = asset["browser_download_url"]
    expected_prefix = f"https://github.com/{PROVIDERS[provider]['repository']}/releases/download/"
    if not url.startswith(expected_prefix):
        raise ValueError("Unexpected release download URL")
    with urlopen(url, timeout=60) as response:
        archive = response.read()
    digest = asset.get("digest")
    if digest and digest != "sha256:" + hashlib.sha256(archive).hexdigest():
        raise ValueError("Release archive checksum mismatch")
    executable_name = provider + (".exe" if system == "windows" else "")
    # Extract only the executable bytes; archive paths and links are never installed.
    if asset["name"].lower().endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            matches = [name for name in bundle.namelist() if name.split("/")[-1] == executable_name]
            if len(matches) != 1:
                raise ValueError("Expected exactly one executable in release archive")
            binary = bundle.read(matches[0])
    else:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            matches = [member for member in bundle.getmembers()
                       if member.isfile() and member.name.split("/")[-1] == executable_name]
            if len(matches) != 1:
                raise ValueError("Expected exactly one executable in release archive")
            with bundle.extractfile(matches[0]) as source:
                binary = source.read()
    destination.mkdir(parents=True, exist_ok=True)
    executable = destination / executable_name
    executable.write_bytes(binary)
    executable.chmod(0o755)
    return executable


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    monitor = commands.add_parser("monitor")
    monitor.add_argument("--output", type=Path, required=True)
    monitor.add_argument("--provider", choices=PROVIDERS)
    monitor.add_argument("--version")
    install = commands.add_parser("install")
    install.add_argument("provider", choices=PROVIDERS)
    install.add_argument("version")
    install.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "install":
        print(install_release(args.provider, args.version, args.destination))
        return
    updates, matrix = collect_updates(args.provider, args.version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"providers": updates, "matrix": matrix}, indent=2) + "\n",
        encoding="utf-8",
    )
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"matrix={json.dumps(matrix)}\n")
    print(json.dumps(updates, indent=2))


if __name__ == "__main__":
    main()
