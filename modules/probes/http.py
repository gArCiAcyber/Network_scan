"""HTTP protocol probing helpers."""

import socket

from modules.probes.generic import send_probe_and_grab_banner


def build_http_head_request(target_host: str) -> bytes:
    """Build a minimal HTTP HEAD request for banner discovery."""
    return (
        "HEAD / HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        "User-Agent: hylianscan\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii", errors="ignore")


def grab_http_banner(client: socket.socket, target_host: str) -> str | None:
    """Actively request HTTP headers from a web service."""
    return send_probe_and_grab_banner(client, build_http_head_request(target_host))
