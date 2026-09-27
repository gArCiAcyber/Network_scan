"""HTTP protocol probing helpers."""

import ipaddress
import socket

from modules.probes.generic import send_probe_and_grab_banner
from modules.target import normalize_host_identity


def build_http_head_request(target_host: str, port: int | None = None) -> bytes:
    """Build a minimal HTTP HEAD request for banner discovery."""
    target_host = normalize_host_identity(target_host)
    host = target_host

    try:
        if ipaddress.ip_address(target_host).version == 6:
            host = f"[{target_host}]"
    except ValueError:
        pass

    if port is not None and port not in (80, 443):
        host = f"{host}:{port}"

    return (
        "HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: hylianscan\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")


def grab_http_banner(client: socket.socket, target_host: str, port: int | None = None) -> str | None:
    """Actively request HTTP headers from a web service."""
    return send_probe_and_grab_banner(
        client,
        build_http_head_request(target_host, port),
        end_marker=b"\r\n\r\n",
    )
