"""TLS wrapping and metadata collection helpers."""

import socket
import ssl
from typing import Any

from modules.probes.certificates import build_certificate_metadata, build_cipher_metadata
from modules.probes.generic import (
    grab_banner,
    merge_banner_parts,
    send_probe_and_grab_banner,
)


def build_tls_context() -> ssl.SSLContext:
    """Create a TLS context for metadata collection without trust enforcement."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def collect_tls_metadata(tls_client: ssl.SSLSocket) -> dict[str, Any]:
    """Collect certificate and handshake metadata from a TLS socket."""
    der_certificate = tls_client.getpeercert(binary_form=True)

    if der_certificate is None:
        return {
            "status": "no_certificate",
            "handshake": {
                "protocol": tls_client.version(),
                "cipher": build_cipher_metadata(tls_client.cipher()),
            },
            "certificate": {},
            "error": None,
        }

    return {
        "status": "collected",
        "handshake": {
            "protocol": tls_client.version(),
            "cipher": build_cipher_metadata(tls_client.cipher()),
        },
        "certificate": build_certificate_metadata(der_certificate),
        "error": None,
    }


def grab_tls_metadata(
    client: socket.socket,
    server_hostname: str,
) -> dict[str, Any]:
    """Collect TLS handshake and certificate metadata from a connected socket."""
    context = build_tls_context()

    try:
        with context.wrap_socket(
            client,
            server_hostname=server_hostname,
        ) as tls_client:
            return collect_tls_metadata(tls_client)
    except (OSError, ValueError, ssl.SSLError) as error:
        return {
            "status": "failed",
            "handshake": {},
            "certificate": {},
            "error": str(error),
        }


def grab_tls_protocol_banner(
    client: socket.socket,
    server_hostname: str,
    probe_payload: bytes | None = None,
) -> tuple[str | None, dict[str, Any]]:
    """Collect TLS metadata and optionally probe the wrapped service."""
    context = build_tls_context()

    try:
        with context.wrap_socket(
            client,
            server_hostname=server_hostname,
        ) as tls_client:
            tls_metadata = collect_tls_metadata(tls_client)

            if probe_payload is None:
                return None, tls_metadata

            banner = send_probe_and_grab_banner(tls_client, probe_payload)
            return banner, tls_metadata
    except (OSError, ValueError, ssl.SSLError) as error:
        return None, {
            "status": "failed",
            "handshake": {},
            "certificate": {},
            "error": str(error),
        }


def grab_tls_text_service_banner(
    client: socket.socket,
    server_hostname: str,
    probe_payload: bytes,
) -> tuple[str | None, dict[str, Any]]:
    """Collect TLS metadata, service greeting, and text-protocol probe output."""
    context = build_tls_context()

    try:
        with context.wrap_socket(
            client,
            server_hostname=server_hostname,
        ) as tls_client:
            tls_metadata = collect_tls_metadata(tls_client)
            greeting = grab_banner(tls_client)
            probe_response = send_probe_and_grab_banner(tls_client, probe_payload)
            banner = merge_banner_parts(greeting, probe_response)
            return banner, tls_metadata
    except (OSError, ValueError, ssl.SSLError) as error:
        return None, {
            "status": "failed",
            "handshake": {},
            "certificate": {},
            "error": str(error),
        }
