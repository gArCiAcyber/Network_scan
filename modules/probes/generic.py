"""Generic socket banner helpers."""

import re
import socket
import time
from collections.abc import Callable
from contextvars import ContextVar


BANNER_SIZE = 1024
# ponytail: 64 KiB caps banner memory; stream responses if full bodies become necessary.
MAX_BANNER_SIZE = 65536


PROBE_DEADLINE: ContextVar[float | None] = ContextVar("probe_deadline", default=None)
PROBE_CANCEL: ContextVar = ContextVar("probe_cancel", default=None)
COLLECTION_ERRORS: ContextVar = ContextVar("collection_errors", default=None)
COLLECTED_RESPONSES: ContextVar = ContextVar("collected_responses", default=None)


def limit_socket_timeout(client: socket.socket, deadline: float | None = None) -> None:
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
    """Return True when a text-protocol reply has its terminating line."""
    if protocol in {"smtp", "ftp"}:
        return bool(re.search(rb"(?m)^\d{3} [^\r\n]*\r?\n", data))
    if protocol == "imap":
        return bool(re.search(rb"(?im)^a00[12] (?:OK|NO|BAD)[^\r\n]*\r?\n", data))
    if protocol == "pop3":
        return data.endswith(b"\r\n.\r\n") or data.startswith(b"-ERR") and data.endswith(b"\r\n")
    return data.endswith(b"\r\n")


_protocol_response_complete = response_complete


def http_head_complete(data: bytes) -> bool:
    """Return True once the final HTTP response head, not an interim 1xx, is buffered."""
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


def _read_complete(
    data: bytes,
    end_marker: bytes | Callable[[bytes], bool] | None,
    response_complete_fn: Callable[[bytes], bool] | None,
) -> bool:
    """Decide whether the buffered bytes satisfy the caller's terminator."""
    if response_complete_fn is not None:
        return bool(response_complete_fn(data))
    if callable(end_marker):
        return bool(end_marker(data))
    if end_marker == b"\r\n\r\n":
        return http_head_complete(data)
    return end_marker is None or end_marker in data


def grab_banner(
    client: socket.socket,
    end_marker: bytes | Callable[[bytes], bool] | None = None,
    *,
    response_complete: Callable[[bytes], bool] | None = None,
    preserve_lines: bool = False,
) -> str | None:
    """Attempt passive banner grabbing on an open TCP socket."""
    data = bytearray()
    original_timeout = client.gettimeout()
    deadline = PROBE_DEADLINE.get()
    if deadline is None:
        timeout = original_timeout if isinstance(original_timeout, (int, float)) else 10.0
        deadline = time.monotonic() + timeout

    complete = False
    try:
        while len(data) < MAX_BANNER_SIZE:
            limit_socket_timeout(client, deadline)
            chunk = client.recv(min(BANNER_SIZE, MAX_BANNER_SIZE - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            complete = _read_complete(bytes(data), end_marker, response_complete)
            if complete:
                break
    except OSError as error:
        errors = COLLECTION_ERRORS.get()
        if errors is not None:
            errors.append(str(error) or type(error).__name__)
    finally:
        try:
            client.settimeout(original_timeout)
        except OSError:
            pass

    errors = COLLECTION_ERRORS.get()
    if (end_marker is not None or response_complete is not None) and not complete and errors is not None:
        errors.append("Response ended before its terminator or reached the collection limit.")
    responses = COLLECTED_RESPONSES.get()
    if responses is not None and data:
        responses.append(bytes(data))

    raw = bytes(data)
    if preserve_lines or end_marker == b"\r\n\r\n" or (
        end_marker is None and response_complete is None
    ):
        banner = raw.decode("utf-8", errors="replace")
    else:
        banner = clean_banner(raw)
    return banner or None


def send_probe_and_grab_banner(
    client: socket.socket,
    payload: bytes,
    end_marker: bytes | Callable[[bytes], bool] | None = None,
    *,
    response_complete: Callable[[bytes], bool] | None = None,
    preserve_lines: bool = False,
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

    if end_marker is None and response_complete is None:
        command = payload.split()[0] if payload.split() else b""
        protocol = {
            b"EHLO": "smtp",
            b"STARTTLS": "smtp",
            b"CAPA": "pop3",
            b"a001": "imap",
            b"a002": "imap",
            b"AUTH": "ftp",
            b"SYST": "ftp",
            b"STLS": "line",
        }.get(command)
        if protocol:
            end_marker = lambda data, protocol=protocol: _protocol_response_complete(data, protocol)

    keep_lines = preserve_lines or response_complete is not None or callable(end_marker)
    return grab_banner(
        client,
        end_marker,
        response_complete=response_complete,
        preserve_lines=keep_lines,
    )


def merge_banner_parts(*parts: str | None) -> str | None:
    """Join unique banner fragments into one compact display string."""
    clean_parts: list[str] = []

    for part in parts:
        if part and part not in clean_parts:
            clean_parts.append(part)

    if not clean_parts:
        return None

    return " | ".join(clean_parts)
