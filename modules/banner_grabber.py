"""TCP banner grabbing helpers for hylianscan."""

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
