"""HTTP security-header observation helpers."""

from collections.abc import Mapping, Sequence
from typing import Any


HTTP_SECURITY_HEADERS = (
    (
        "strict-transport-security",
        "Strict-Transport-Security",
        "missing_strict_transport_security",
        True,
    ),
    (
        "content-security-policy",
        "Content-Security-Policy",
        "missing_content_security_policy",
        False,
    ),
    (
        "x-frame-options",
        "X-Frame-Options",
        "missing_x_frame_options",
        False,
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options",
        "missing_x_content_type_options",
        False,
    ),
    (
        "referrer-policy",
        "Referrer-Policy",
        "missing_referrer_policy",
        False,
    ),
    (
        "permissions-policy",
        "Permissions-Policy",
        "missing_permissions_policy",
        False,
    ),
    (
        "cross-origin-opener-policy",
        "Cross-Origin-Opener-Policy",
        "missing_cross_origin_opener_policy",
        False,
    ),
)


def is_https_url(url: str | None) -> bool:
    """Return True when the collected URL clearly uses HTTPS."""
    return bool(url and url.lower().startswith("https://"))


def build_http_security_observations(
    headers: Mapping[str, Sequence[str]],
    url: str | None,
) -> dict[str, Any]:
    """Build factual HTTP security-header observations from collected headers."""
    https_response = is_https_url(url)
    header_documents: dict[str, dict[str, Any]] = {}
    present_headers: list[str] = []
    missing_headers: list[str] = []
    observations: list[str] = []

    for header_key, header_name, missing_observation, https_only in HTTP_SECURITY_HEADERS:
        values = list(headers.get(header_key, []))
        present = bool(values)
        expected = not https_only or https_response
        header_observations: list[str] = []

        if present:
            present_headers.append(header_key)
        elif expected:
            missing_headers.append(header_key)
            header_observations.append(missing_observation)
            observations.append(missing_observation)
        elif https_only:
            header_observations.append("not_expected_on_plain_http")

        header_documents[header_key] = {
            "name": header_name,
            "present": present,
            "expected": expected,
            "values": values,
            "observations": header_observations,
        }

    return {
        "headers": header_documents,
        "present": present_headers,
        "missing": missing_headers,
        "observations": observations,
    }
