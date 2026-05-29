"""Passive subdomain discovery integration for hylianscan."""

import subprocess


def run_subfinder(domain: str) -> list[str]:
    """Run Subfinder passive discovery and return clean subdomain results."""
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return []
    except subprocess.SubprocessError:
        return []

    if result.returncode != 0:
        return []

    subdomains: list[str] = []
    seen: set[str] = set()

    for line in result.stdout.splitlines():
        subdomain = line.strip().lower()

        if not subdomain or subdomain in seen:
            continue

        seen.add(subdomain)
        subdomains.append(subdomain)

    return subdomains
