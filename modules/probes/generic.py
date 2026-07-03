"""Generic socket banner helpers."""

import socket


BANNER_SIZE = 1024


def clean_banner(data: bytes) -> str:
    """Decode received service bytes into a compact text banner."""
    text = data.decode("utf-8", errors="replace")
    return " ".join(text.split())


def grab_banner(client: socket.socket) -> str | None:
    """Attempt passive banner grabbing on an open TCP socket."""
    try:
        data = client.recv(BANNER_SIZE)
    except socket.timeout:
        return None
    except OSError:
        return None

    banner = clean_banner(data)
    return banner or None


def send_probe_and_grab_banner(client: socket.socket, payload: bytes) -> str | None:
    """Send a lightweight protocol probe and read the immediate response."""
    try:
        client.sendall(payload)
    except (OSError, socket.timeout):
        return None

    return grab_banner(client)


def merge_banner_parts(*parts: str | None) -> str | None:
    """Join unique banner fragments into one compact display string."""
    clean_parts: list[str] = []

    for part in parts:
        if part and part not in clean_parts:
            clean_parts.append(part)

    if not clean_parts:
        return None

    return " | ".join(clean_parts)
