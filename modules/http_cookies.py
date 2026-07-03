"""HTTP Set-Cookie parsing helpers."""

from collections.abc import Mapping, Sequence
from typing import Any


def parse_cookie_attributes(attribute_parts: Sequence[str]) -> dict[str, str | bool]:
    """Parse Set-Cookie attribute parts into a normalized mapping."""
    attributes: dict[str, str | bool] = {}

    for attribute_part in attribute_parts:
        attribute = attribute_part.strip()

        if not attribute:
            continue

        if "=" in attribute:
            name, value = attribute.split("=", maxsplit=1)
            attributes[name.strip().lower()] = value.strip()
        else:
            attributes[attribute.lower()] = True

    return attributes


def build_cookie_security_observations(
    name: str,
    secure: bool,
    httponly: bool,
    samesite: str | None,
    path: str | None,
    domain: str | None,
) -> list[str]:
    """Build simple cookie security observations."""
    observations: list[str] = []

    if not secure:
        observations.append("missing_secure")

    if not httponly:
        observations.append("missing_httponly")

    if samesite is None:
        observations.append("missing_samesite")

    if name.startswith("__Host-") and secure and path == "/" and domain is None:
        observations.append("host_prefix_valid")

    if name.startswith("__Secure-") and secure:
        observations.append("secure_prefix_valid")

    return observations


def parse_set_cookie_header(header_value: str) -> dict[str, Any] | None:
    """Parse one Set-Cookie header into structured metadata."""
    parts = [part.strip() for part in header_value.split(";")]

    if not parts or not parts[0]:
        return None

    name_value = parts[0]
    if "=" in name_value:
        name, value = name_value.split("=", maxsplit=1)
        cookie_name = name.strip()
        value_present = bool(value)
    else:
        cookie_name = name_value.strip()
        value_present = False

    if not cookie_name:
        return None

    attributes = parse_cookie_attributes(parts[1:])
    secure = bool(attributes.get("secure"))
    httponly = bool(attributes.get("httponly"))
    samesite = attributes.get("samesite")
    path = attributes.get("path")
    domain = attributes.get("domain")
    expires = attributes.get("expires")
    max_age = attributes.get("max-age")

    return {
        "name": cookie_name,
        "value_present": value_present,
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite if isinstance(samesite, str) else None,
        "path": path if isinstance(path, str) else None,
        "domain": domain if isinstance(domain, str) else None,
        "expires": expires if isinstance(expires, str) else None,
        "max_age": max_age if isinstance(max_age, str) else None,
        "uses_host_prefix": cookie_name.startswith("__Host-"),
        "uses_secure_prefix": cookie_name.startswith("__Secure-"),
        "security_observations": build_cookie_security_observations(
            name=cookie_name,
            secure=secure,
            httponly=httponly,
            samesite=samesite if isinstance(samesite, str) else None,
            path=path if isinstance(path, str) else None,
            domain=domain if isinstance(domain, str) else None,
        ),
    }


def parse_http_cookies(headers: Mapping[str, Sequence[str]]) -> list[dict[str, Any]]:
    """Parse Set-Cookie headers into structured cookie metadata."""
    cookies: list[dict[str, Any]] = []

    for header_value in headers.get("set-cookie", []):
        cookie = parse_set_cookie_header(header_value)

        if cookie is not None:
            cookies.append(cookie)

    return cookies
