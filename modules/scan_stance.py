"""TCP scan stance profiles for hylianscan."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanStance:
    """Resolved TCP scan stance settings."""

    name: str
    lore_alias: str
    workers: int
    timeout: float


STANCE_ALIASES: dict[str, str] = {
    "fast": "fast",
    "din": "fast",
    "balanced": "balanced",
    "nayru": "balanced",
    "stealthier": "stealthier",
    "farore": "stealthier",
}

STANCE_PROFILES: dict[str, ScanStance] = {
    "fast": ScanStance(
        name="fast",
        lore_alias="Din",
        workers=200,
        timeout=0.75,
    ),
    "balanced": ScanStance(
        name="balanced",
        lore_alias="Nayru",
        workers=50,
        timeout=1.0,
    ),
    "stealthier": ScanStance(
        name="stealthier",
        lore_alias="Farore",
        workers=10,
        timeout=2.0,
    ),
}


def list_scan_stances() -> tuple[ScanStance, ...]:
    """Return built-in scan stances in display order."""
    return tuple(STANCE_PROFILES.values())


def resolve_stance(
    stance_value: str,
    explicit_workers: int | None = None,
    explicit_timeout: float | None = None,
) -> ScanStance:
    """Resolve a stance name or lore alias into effective scan settings."""
    normalized_value = stance_value.strip().lower()
    profile_name = STANCE_ALIASES.get(normalized_value)

    if profile_name is None:
        valid_values = ", ".join(sorted(STANCE_ALIASES))
        raise ValueError(f"Invalid --stance value. Use one of: {valid_values}.")

    profile = STANCE_PROFILES[profile_name]

    return ScanStance(
        name=profile.name,
        lore_alias=profile.lore_alias,
        workers=explicit_workers if explicit_workers is not None else profile.workers,
        timeout=explicit_timeout if explicit_timeout is not None else profile.timeout,
    )
