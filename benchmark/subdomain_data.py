"""Deterministic Hylianlab inputs and an oracle independent of provider parsing."""

import re


DOMAIN = "hylianlab.test"
GENERATOR_VERSION = 1
SEED = 0
SIZES = (1_000, 10_000, 100_000)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


def in_scope(name: str) -> bool:
    """Accept canonical ASCII hostnames in the lab, including its base domain."""
    return (isinstance(name, str) and len(name) <= 253
            and (name == DOMAIN or name.endswith("." + DOMAIN))
            and all(_LABEL.fullmatch(label) for label in name.split(".")))


def build_dataset(size: int) -> dict:
    """Return exact provider memberships and expected attribution for one load."""
    if type(size) is not int or size not in SIZES:
        raise ValueError("Hylianlab dataset size must be 1000, 10000, or 100000.")

    longest = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 46, DOMAIN])
    names = [DOMAIN, f"api.{DOMAIN}", f"mail.{DOMAIN}", f"api.dev.europa.{DOMAIN}",
             f"xn--bcher-kva.{DOMAIN}", f"{'z' * 63}.{DOMAIN}", longest]
    # No PRNG: the recorded seed is the starting numeric identifier.
    names.extend((f"server{index:06d}.{DOMAIN}" if index % 2 == 0 else
                  f"api{index:06d}.dev.europa.{DOMAIN}")
                 for index in range(SEED, SEED + size - len(names)))

    shared, subfinder_end = size * 3 // 10, size * 7 // 10
    providers = {
        "subfinder": sorted(names[:subfinder_end]),
        "amass": sorted(names[:shared] + names[subfinder_end:]),
    }
    provider_sets = {provider: set(values) for provider, values in providers.items()}
    union = sorted(names)
    sources = {name: sorted(provider for provider, values in provider_sets.items()
                            if name in values) for name in union}
    rejected = [
        "outside.test", f"api.{DOMAIN}.evil.test", f"not-{DOMAIN}",
        f"https://api.{DOMAIN}", f"*.{DOMAIN}", f"bad..{DOMAIN}",
        f"-bad.{DOMAIN}", f"bad-.{DOMAIN}", f"bad_name.{DOMAIN}",
        f"{'x' * 64}.{DOMAIN}", "x" + longest,
        f"api.{DOMAIN}:443", f"api.{DOMAIN}/path", f"api .{DOMAIN}",
    ]
    return {"domain": DOMAIN, "size": size, "generator_version": GENERATOR_VERSION,
            "seed": SEED, "union": union, "providers": providers,
            "sources": sources, "rejected": rejected}
