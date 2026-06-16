"""Predefined TCP port profiles for common authorized recon workflows."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PortProfile:
    """Resolved TCP port profile settings."""

    name: str
    alias: str
    description: str
    ports: tuple[int, ...]


def normalize_profile_ports(ports: list[int]) -> tuple[int, ...]:
    """Deduplicate and sort one profile port list."""
    return tuple(sorted({int(port) for port in ports}))


PORT_PROFILES: dict[str, PortProfile] = {
    "quick": PortProfile(
        name="quick",
        alias="kokiri",
        description="Small fast triage set for common exposed services.",
        ports=normalize_profile_ports(
            [
                21,
                22,
                25,
                53,
                80,
                110,
                143,
                443,
                445,
                587,
                993,
                995,
                3306,
                3389,
                8080,
                8443,
            ]
        ),
    ),
    "web": PortProfile(
        name="web",
        alias="sheikah",
        description="Common HTTP, HTTPS, and alternate web application ports.",
        ports=normalize_profile_ports(
            [
                80,
                443,
                2052,
                2053,
                2082,
                2083,
                2086,
                2087,
                2095,
                2096,
                3000,
                5000,
                5001,
                5601,
                8000,
                8008,
                8080,
                8081,
                8088,
                8090,
                8443,
                8880,
                8888,
                9000,
                9090,
                9200,
                9443,
                10000,
            ]
        ),
    ),
    "mail": PortProfile(
        name="mail",
        alias="rito",
        description="SMTP, SMTPS, submission, IMAP, IMAPS, POP3, and POP3S.",
        ports=normalize_profile_ports([25, 110, 143, 465, 587, 993, 995, 2525]),
    ),
    "admin": PortProfile(
        name="admin",
        alias="castle",
        description="Common admin panels, control panels, and remote-management ports.",
        ports=normalize_profile_ports(
            [
                22,
                23,
                80,
                443,
                623,
                2222,
                2375,
                2376,
                3389,
                5000,
                5001,
                5900,
                5901,
                5985,
                5986,
                8000,
                8080,
                8081,
                8443,
                9090,
                10000,
                2082,
                2083,
                2086,
                2087,
            ]
        ),
    ),
    "bugbounty": PortProfile(
        name="bugbounty",
        alias="triforce",
        description="Practical mixed triage set for bug bounty recon.",
        ports=normalize_profile_ports(
            [
                21,
                22,
                23,
                25,
                53,
                80,
                110,
                143,
                443,
                445,
                465,
                587,
                993,
                995,
                1433,
                1521,
                2049,
                2052,
                2053,
                2082,
                2083,
                2086,
                2087,
                2095,
                2096,
                2222,
                2375,
                2376,
                2525,
                3000,
                3306,
                3389,
                5432,
                5601,
                5900,
                5984,
                5985,
                5986,
                6379,
                8000,
                8008,
                8080,
                8081,
                8088,
                8090,
                8443,
                8880,
                8888,
                9000,
                9090,
                9200,
                9300,
                9443,
                10000,
                11211,
                15672,
                27017,
            ]
        ),
    ),
}

PORT_PROFILE_ALIASES: dict[str, str] = {
    profile.name: profile.name for profile in PORT_PROFILES.values()
}
PORT_PROFILE_ALIASES.update(
    {profile.alias: profile.name for profile in PORT_PROFILES.values()}
)


def get_valid_port_profile_values() -> tuple[str, ...]:
    """Return valid profile names and aliases for error messages."""
    return tuple(sorted(PORT_PROFILE_ALIASES))


def resolve_port_profile(profile_value: str) -> PortProfile:
    """Resolve a technical profile name or Zelda alias."""
    normalized_value = profile_value.strip().lower()
    profile_name = PORT_PROFILE_ALIASES.get(normalized_value)

    if profile_name is None:
        valid_values = ", ".join(get_valid_port_profile_values())
        raise ValueError(
            f"Invalid --port-profile value. Use one of: {valid_values}."
        )

    return PORT_PROFILES[profile_name]


def format_port_profile_label(profile_value: str) -> str:
    """Return a human-readable profile label."""
    profile = resolve_port_profile(profile_value)
    return f"{profile.name} / {profile.alias}"
