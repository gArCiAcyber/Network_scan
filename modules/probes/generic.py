"""Generic socket banner helpers."""

import socket


BANNER_SIZE = 1024
# ponytail: 64 KiB caps banner memory; stream responses if full bodies become necessary.
MAX_BANNER_SIZE = 65536


def clean_banner(data: bytes) -> str:
    """Decode received service bytes into a compact text banner."""
    text = data.decode("utf-8", errors="replace")
    return " ".join(text.split())


def grab_banner(client: socket.socket, end_marker: bytes | None = None) -> str | None:
    """Attempt passive banner grabbing on an open TCP socket."""
    data = bytearray()

    try:
        while len(data) < MAX_BANNER_SIZE:
            chunk = client.recv(min(BANNER_SIZE, MAX_BANNER_SIZE - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if end_marker is None or end_marker in data:
                break
    except socket.timeout:
        pass
    except OSError:
        pass

    banner = clean_banner(bytes(data))
    return banner or None


def send_probe_and_grab_banner(
    client: socket.socket,
    payload: bytes,
    end_marker: bytes | None = None,
) -> str | None:
    """Send a lightweight protocol probe and read the immediate response."""
    try:
        client.sendall(payload)
    except (OSError, socket.timeout):
        return None

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
