"""Complete built-in scan profiles for common recon workflows."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    """Defaults applied together by one named scan profile."""

    name: str
    description: str
    port_profile: str
    stance: str
    workers: int
    timeout: float
    max_rate: float | None
    host_discovery: str | None
    http_probing: bool


SCAN_PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Fast first pass over common services.",
        port_profile="quick",
        stance="balanced",
        workers=50,
        timeout=0.75,
        max_rate=None,
        host_discovery=None,
        http_probing=False,
    ),
    "web": ScanProfile(
        name="web",
        description="Balanced web-focused scan with HTTP probing.",
        port_profile="web",
        stance="balanced",
        workers=50,
        timeout=1.0,
        max_rate=None,
        host_discovery=None,
        http_probing=True,
    ),
    "cautious": ScanProfile(
        name="cautious",
        description="Low-rate scan of selected common services.",
        port_profile="quick",
        stance="stealthier",
        workers=10,
        timeout=2.0,
        max_rate=10.0,
        host_discovery=None,
        http_probing=True,
    ),
}


def list_scan_profiles() -> tuple[ScanProfile, ...]:
    """Return built-in scan profiles in display order."""
    return tuple(SCAN_PROFILES.values())


def resolve_scan_profile(profile_value: str) -> ScanProfile:
    """Resolve a scan profile name."""
    normalized_value = profile_value.strip().lower()

    try:
        return SCAN_PROFILES[normalized_value]
    except KeyError as error:
        valid_values = ", ".join(SCAN_PROFILES)
        raise ValueError(
            f"Invalid --profile value. Use one of: {valid_values}."
        ) from error
