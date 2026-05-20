"""Target validation and DNS resolution for hylianscan."""

import ipaddress
import socket
from dataclasses import dataclass


class TargetResolutionError(ValueError):
    """Raised when a target cannot be resolved to an IPv4 address."""


@dataclass(frozen=True)
class TargetInfo:
    """Normalized target information used by the scanner."""

    raw_input: str
    target_host: str
    resolved_ip: str
    is_ip_address: bool


def normalize_target(value: str) -> str:
    """Trim user input before validation."""
    return value.strip()


def is_ip_address(value: str) -> bool:
    """Return True when the value is a valid IP address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False

    return True


def validate_target(value: str) -> str:
    """Validate that the target is not empty."""
    normalized_value = normalize_target(value)

    if not normalized_value:
        raise TargetResolutionError("No target was provided.")

    return normalized_value


def resolve_target(value: str) -> TargetInfo:
    """Resolve a host or IP address to scanner-ready target information."""
    target = validate_target(value)

    if is_ip_address(target):
        return TargetInfo(
            raw_input=value,
            target_host=target,
            resolved_ip=target,
            is_ip_address=True,
        )

    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror as error:
        raise TargetResolutionError(f"Could not resolve target: {target}") from error

    return TargetInfo(
        raw_input=value,
        target_host=target,
        resolved_ip=resolved_ip,
        is_ip_address=False,
    )


def format_target_orientation(target: TargetInfo) -> str:
    """Build a clean Host/IP orientation block."""
    if target.is_ip_address:
        return "\n".join(
            [
                "[*] Target Orientation:",
                f"    Direct IP : {target.resolved_ip}",
            ]
        )

    return "\n".join(
        [
            "[*] Target Orientation:",
            f"    Host        : {target.target_host}",
            f"    Resolved IP : {target.resolved_ip}",
        ]
    )

