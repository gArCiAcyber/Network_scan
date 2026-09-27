"""Generic socket banner helpers."""

import socket
import time
from collections.abc import Callable


BANNER_SIZE = 1024
# ponytail: 64 KiB caps banner memory; stream responses if full bodies become necessary.
MAX_BANNER_SIZE = 65536


def clean_banner(data: bytes) -> str:
    """Decode received service bytes into a compact text banner."""
    text = data.decode("utf-8", errors="replace")
    return " ".join(text.split())


def grab_banner(
    client: socket.socket,
    end_marker: bytes | None = None,
    *,
    response_complete: Callable[[bytes], bool] | None = None,
    preserve_lines: bool = False,
) -> str | None:
    """Attempt passive banner grabbing on an open TCP socket."""
    data = bytearray()
    timeout = client.gettimeout()
    deadline = time.monotonic() + timeout if timeout is not None else None

    try:
        while len(data) < MAX_BANNER_SIZE:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                client.settimeout(remaining)
            chunk = client.recv(min(BANNER_SIZE, MAX_BANNER_SIZE - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if response_complete is not None:
                if response_complete(bytes(data)):
                    break
            elif end_marker is None or end_marker in data:
                break
    except socket.timeout:
        pass
    except OSError:
        pass
    finally:
        try:
            client.settimeout(timeout)
        except OSError:
            pass

    banner = data.decode("utf-8", errors="replace") if preserve_lines else clean_banner(bytes(data))
    return banner or None


def send_probe_and_grab_banner(
    client: socket.socket,
    payload: bytes,
    end_marker: bytes | None = None,
    *,
    response_complete: Callable[[bytes], bool] | None = None,
    preserve_lines: bool = False,
) -> str | None:
    """Send a lightweight protocol probe and read the immediate response."""
    try:
        client.sendall(payload)
    except (OSError, socket.timeout):
        return None

    return grab_banner(
        client, end_marker=end_marker,
        response_complete=response_complete, preserve_lines=preserve_lines,
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
