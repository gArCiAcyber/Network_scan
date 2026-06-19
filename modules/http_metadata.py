"""Shared primitive HTTP response parsing for hylianscan."""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass


HTTP_STATUS_LINE_PATTERN = re.compile(
    r"^HTTP/(?P<version>\S+)\s+"
    r"(?P<status_code>\d{3})"
    r"(?:[ \t]+(?P<reason_phrase>.*))?$"
)
COMPACT_HTTP_STATUS_PATTERN = re.compile(
    r"^HTTP/(?P<version>\S+)\s+"
    r"(?P<status_code>\d{3})"
    r"(?:\s+(?P<reason_phrase>.*?))?"
    r"(?=\s+[A-Za-z][A-Za-z0-9-]*:\s+|$)"
)
HTTP_HEADER_PATTERN = re.compile(
    r"(?<!\S)(?P<name>[A-Za-z][A-Za-z0-9-]*):\s+"
)


@dataclass(frozen=True)
class HTTPResponseHead:
    """Structured HTTP status line and compact response headers."""

    protocol: str
    status_code: int
    reason_phrase: str | None
    headers: dict[str, list[str]]


def append_header(headers: dict[str, list[str]], name: str, value: str) -> None:
    """Append one normalized HTTP header value."""
    header_name = name.lower()
    header_value = " ".join(value.split())

    if not header_value:
        return

    headers.setdefault(header_name, []).append(header_value)


def parse_http_headers(header_block: str) -> dict[str, list[str]]:
    """Parse compact or line-delimited headers into a normalized mapping."""
    headers: dict[str, list[str]] = {}
    matches = list(HTTP_HEADER_PATTERN.finditer(header_block))

    for index, match in enumerate(matches):
        value_start = match.end()
        value_end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(header_block)
        )
        append_header(
            headers=headers,
            name=match.group("name"),
            value=header_block[value_start:value_end],
        )

    return headers


def get_first_header(
    headers: Mapping[str, Sequence[str]],
    name: str,
) -> str | None:
    """Return the first value for a normalized HTTP header name."""
    values = headers.get(name.lower())

    if not values:
        return None

    return values[0]


def parse_http_response_head(response: str | None) -> HTTPResponseHead | None:
    """Parse the status line and headers from an HTTP response or compact banner."""
    if response is None:
        return None

    if "\n" in response:
        status_line, header_block = response.split("\n", maxsplit=1)
        status_match = HTTP_STATUS_LINE_PATTERN.match(status_line.rstrip("\r"))
    else:
        status_match = COMPACT_HTTP_STATUS_PATTERN.match(response)
        header_block = response[status_match.end():] if status_match else ""

    if status_match is None:
        return None

    reason_phrase = (
        " ".join((status_match.group("reason_phrase") or "").split()) or None
    )
    return HTTPResponseHead(
        protocol=f"HTTP/{status_match.group('version')}",
        status_code=int(status_match.group("status_code")),
        reason_phrase=reason_phrase,
        headers=parse_http_headers(header_block),
    )


def extract_http_status_code(response: str | None) -> int | None:
    """Return an HTTP status code without exposing report/export concerns."""
    response_head = parse_http_response_head(response)
    return response_head.status_code if response_head is not None else None


def extract_http_header(response: str | None, name: str) -> str | None:
    """Return one normalized header value from an HTTP response."""
    response_head = parse_http_response_head(response)

    if response_head is None:
        return None

    return get_first_header(response_head.headers, name)
