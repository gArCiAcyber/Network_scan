"""Plain-text renderers for information-only CLI commands."""

import argparse

from modules.port_profiles import list_port_profiles
from modules.scan_stance import list_scan_stances


def format_port_profiles_listing() -> str:
    """Return plain-text details for built-in TCP port profiles."""
    lines = ["Built-in TCP port profiles:"]

    for profile in list_port_profiles():
        ports = ", ".join(str(port) for port in profile.ports)
        lines.extend(
            [
                "",
                f"{profile.name} / {profile.alias}",
                f"  Description : {profile.description}",
                f"  Port Count  : {len(profile.ports)}",
                f"  Ports       : {ports}",
            ]
        )

    return "\n".join(lines)


def format_scan_stances_listing() -> str:
    """Return plain-text details for built-in TCP scan stances."""
    lines = ["Built-in TCP scan stances:"]

    for stance in list_scan_stances():
        lines.extend(
            [
                "",
                f"{stance.name} / {stance.lore_alias.lower()}",
                f"  Workers : {stance.workers}",
                f"  Timeout : {stance.timeout:.2f}s",
            ]
        )

    return "\n".join(lines)


def build_information_command_output(args: argparse.Namespace) -> str:
    """Return the complete output for selected information-only commands."""
    sections: list[str] = []

    if getattr(args, "list_port_profiles", False):
        sections.append(format_port_profiles_listing())

    if getattr(args, "list_stances", False):
        sections.append(format_scan_stances_listing())

    return "\n\n".join(sections)
