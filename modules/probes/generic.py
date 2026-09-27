"""Generic socket banner helpers."""

import socket
import re
import time
from contextvars import ContextVar
from collections.abc import Callable


BANNER_SIZE = 1024
# ponytail: 64 KiB caps banner memory; stream responses if full bodies become necessary.
MAX_BANNER_SIZE = 65536


PROBE_DEADLINE: ContextVar[float | None] = ContextVar("probe_deadline", default=None)
PROBE_CANCEL = ContextVar("probe_cancel", default=None)
COLLECTION_ERRORS = ContextVar("collection_errors", default=None)
COLLECTED_RESPONSES = ContextVar("collected_responses", default=None)


def limit_socket_timeout(client, deadline=None):
    """Apply the remaining collection budget to the next blocking operation."""
    cancel = PROBE_CANCEL.get()
    if cancel is not None and cancel.is_set():
        raise socket.timeout("Probe cancelled.")
    deadline = deadline if deadline is not None else PROBE_DEADLINE.get()
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("Probe deadline exceeded.")
        current = client.gettimeout()
        client.settimeout(min(current, remaining) if isinstance(current, (int, float)) else remaining)


def response_complete(data: bytes, protocol: str) -> bool:
    if protocol in {"smtp", "ftp"}:
        return bool(re.search(rb"(?m)^\d{3} [^\r\n]*\r?\n", data))
    if protocol == "imap":
        return bool(re.search(rb"(?im)^a00[12] (?:OK|NO|BAD)[^\r\n]*\r?\n", data))
    if protocol == "pop3":
        return data.endswith(b"\r\n.\r\n") or data.startswith(b"-ERR") and data.endswith(b"\r\n")
    return data.endswith(b"\r\n")


def http_head_complete(data: bytes) -> bool:
    remaining = data
    while b"\r\n\r\n" in remaining:
        head, remaining = remaining.split(b"\r\n\r\n", 1)
        match = re.match(rb"HTTP/\S+ ([0-9]{3})(?: |\r|$)", head)
        if match is None:
            return True
        code = int(match.group(1))
        if code == 101 or not 100 <= code < 200:
            return True
    return False


def clean_banner(data: bytes) -> str:
    """Decode received service bytes into a compact text banner."""
    text = data.decode("utf-8", errors="replace")
    return " ".join(text.split())


def grab_banner(client: socket.socket, end_marker: bytes | Callable[[bytes], bool] | None = None) -> str | None:
    """Attempt passive banner grabbing on an open TCP socket."""
    data = bytearray()
    operation_timeout = client.gettimeout()
    deadline = PROBE_DEADLINE.get()
    if deadline is None:
        deadline = time.monotonic() + (operation_timeout if isinstance(operation_timeout, (int, float)) else 10.0)

    complete = False
    try:
        while len(data) < MAX_BANNER_SIZE:
            limit_socket_timeout(client, deadline)
            chunk = client.recv(min(BANNER_SIZE, MAX_BANNER_SIZE - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            complete = (
                end_marker(bytes(data)) if callable(end_marker) else
                http_head_complete(bytes(data)) if end_marker == b"\r\n\r\n" else
                end_marker is None or end_marker in data
            )
            if complete:
                break
    except OSError as error:
        errors = COLLECTION_ERRORS.get()
        if errors is not None:
            errors.append(str(error) or type(error).__name__)

    errors = COLLECTION_ERRORS.get()
    if end_marker is not None and not complete and errors is not None:
        errors.append("Response ended before its terminator or reached the collection limit.")
    responses = COLLECTED_RESPONSES.get()
    if responses is not None and data:
        responses.append(bytes(data))

    banner = bytes(data).decode("utf-8", errors="replace")
    return banner or None


def send_probe_and_grab_banner(
    client: socket.socket,
    payload: bytes,
    end_marker: bytes | Callable[[bytes], bool] | None = None,
) -> str | None:
    """Send a lightweight protocol probe and read the immediate response."""
    try:
        limit_socket_timeout(client)
        client.sendall(payload)
    except OSError as error:
        errors = COLLECTION_ERRORS.get()
        if errors is not None:
            errors.append(str(error) or type(error).__name__)
        return None

    if end_marker is None:
        protocol = ({b"EHLO": "smtp", b"STARTTLS": "smtp", b"CAPA": "pop3",
                     b"a001": "imap", b"a002": "imap", b"AUTH": "ftp",
                     b"SYST": "ftp", b"STLS": "line"}).get(payload.split()[0])
        if protocol:
            end_marker = lambda data: response_complete(data, protocol)
    return grab_banner(client, end_marker=end_marker)


def merge_banner_parts(*parts: str | None) -> str | None:
    """Join unique banner fragments into one compact display string."""
    clean_parts: list[str] = []

    for part in parts:
        if part and part not in clean_parts:
            clean_parts.append(part)

    if not clean_parts:
        return None

    return " | ".join(clean_parts)
