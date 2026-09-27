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


@dataclass(frozen=True)
class HTTPResponseHead:
    """Structured HTTP status line and compact response headers."""

    protocol: str
    status_code: int
    reason_phrase: str | None
    headers: dict[str, list[str]]
    complete: bool = False


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
    for line in header_block.splitlines():
        if not line:
            break
        name, separator, value = line.partition(":")
        if separator and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            append_header(headers, name, value)

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

    # A flattened legacy banner has lost its header boundaries. Its status can
    # still be read, but header-looking words cannot establish header evidence.
    if "\n" not in response:
        match = COMPACT_HTTP_STATUS_PATTERN.match(response)
        if match is None or not 100 <= int(match.group("status_code")) <= 599:
            return None
        return HTTPResponseHead(f"HTTP/{match.group('version')}",
            int(match.group("status_code")), match.group("reason_phrase") or None, {}, False)

    remaining = response.replace("\r\n", "\n")
    while remaining:
        head, separator, rest = remaining.partition("\n\n")
        lines = head.split("\n")
        match = HTTP_STATUS_LINE_PATTERN.fullmatch(lines[0])
        if match is None:
            return None
        code = int(match.group("status_code"))
        if not 100 <= code <= 599:
            return None
        if 100 <= code < 200 and code != 101:
            if not separator or not rest:
                return None
            remaining = rest
            continue
        header_block = "\n".join(lines[1:])
        if not separator:
            header_block = header_block.rsplit("\n", 1)[0] if "\n" in header_block else ""
        valid_lines = all(re.fullmatch(r"[!#$%&'\*+.^_`|~0-9A-Za-z-]+:[^\r\n]*", line)
                          for line in lines[1:] if line)
        return HTTPResponseHead(f"HTTP/{match.group('version')}", code,
            match.group("reason_phrase") or None, parse_http_headers(header_block), bool(separator) and valid_lines)
    return None



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
