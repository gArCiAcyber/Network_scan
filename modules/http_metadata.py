"""Shared primitive HTTP response parsing for hylianscan."""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass


HTTP_STATUS_LINE_PATTERN = re.compile(
    r"HTTP/(?P<version>[0-9]\.[0-9])[ \t]+"
    r"(?P<status_code>[1-5][0-9]{2})"
    r"(?:[ \t]+(?P<reason_phrase>[^\x00-\x08\x0a-\x1f\x7f]*))?"
)
HTTP_HEADER_PATTERN = re.compile(
    r"(?P<name>[!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*"
    r"(?P<value>[^\x00-\x08\x0a-\x1f\x7f]*)"
)


@dataclass(frozen=True)
class HTTPResponseHead:
    """Structured HTTP status line and response headers."""

    protocol: str
    status_code: int
    reason_phrase: str | None
    headers: dict[str, list[str]]
    complete: bool = False

    @property
    def headers_complete(self) -> bool:
        """Report whether the header block ended on a blank line."""
        return self.complete


def append_header(headers: dict[str, list[str]], name: str, value: str) -> None:
    """Append one normalized HTTP header value."""
    header_name = name.lower()
    header_value = value.strip(" \t")

    headers.setdefault(header_name, []).append(header_value)


def parse_http_headers(header_block: str) -> dict[str, list[str]]:
    """Parse field lines only, stopping before the response body."""
    headers: dict[str, list[str]] = {}
    previous_name = None
    for line in header_block.replace("\r\n", "\n").split("\n"):
        if not line:
            break
        if line.startswith((" ", "\t")) and previous_name is not None:
            if re.search(r"[\x00-\x08\x0a-\x1f\x7f]", line):
                raise ValueError("Invalid HTTP header continuation")
            headers[previous_name][-1] += " " + line.strip(" \t")
            continue
        match = HTTP_HEADER_PATTERN.fullmatch(line)
        if match is None:
            raise ValueError("Invalid HTTP header line")
        previous_name = match.group("name").lower()
        append_header(headers, previous_name, match.group("value"))

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


def _response_head(
    status_match: re.Match[str],
    headers: dict[str, list[str]],
    complete: bool,
) -> HTTPResponseHead:
    """Build one response head from a matched status line."""
    reason_phrase = " ".join((status_match.group("reason_phrase") or "").split()) or None
    return HTTPResponseHead(
        protocol=f"HTTP/{status_match.group('version')}",
        status_code=int(status_match.group("status_code")),
        reason_phrase=reason_phrase,
        headers=headers,
        complete=complete,
    )


def parse_http_response_head(response: str | None) -> HTTPResponseHead | None:
    """Parse HTTP lines without guessing field boundaries in compact banners."""
    if response is None:
        return None

    normalized = response.replace("\r\n", "\n")
    if "\n" not in normalized:
        status_match = HTTP_STATUS_LINE_PATTERN.fullmatch(normalized)
        if status_match is None:
            return None
        code = int(status_match.group("status_code"))
        if not 100 <= code <= 599:
            return None
        return _response_head(status_match, {}, False)

    remaining = normalized
    while remaining:
        head, separator, rest = remaining.partition("\n\n")
        lines = head.split("\n")
        status_match = HTTP_STATUS_LINE_PATTERN.fullmatch(lines[0])
        if status_match is None:
            return None
        code = int(status_match.group("status_code"))
        if not 100 <= code <= 599:
            return None
        if 100 <= code < 200 and code != 101:
            if not separator or not rest:
                return None
            remaining = rest
            continue
        try:
            headers = parse_http_headers("\n".join(lines[1:]))
        except ValueError:
            return None
        return _response_head(status_match, headers, bool(separator))
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
