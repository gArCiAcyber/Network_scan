"""TCP banner grabbing helpers for hylianscan."""

import hashlib
import os
import socket
import ssl
import tempfile
from typing import Any


BANNER_SIZE = 1024
TLS_METADATA_PORTS = {443, 465, 636, 8443, 989, 990, 993, 995}


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


def should_collect_tls_metadata(port: int) -> bool:
    """Return True when a TCP port is expected to expose TLS metadata."""
    return port in TLS_METADATA_PORTS


def format_certificate_name(
    name_items: tuple[tuple[tuple[str, str], ...], ...] | None,
) -> dict[str, list[str]]:
    """Convert certificate subject or issuer tuples into JSON-ready data."""
    formatted_name: dict[str, list[str]] = {}

    if not name_items:
        return formatted_name

    for relative_distinguished_name in name_items:
        for key, value in relative_distinguished_name:
            formatted_name.setdefault(key, []).append(value)

    return formatted_name


def split_subject_alt_names(
    subject_alt_names: tuple[tuple[str, str], ...] | None,
) -> dict[str, list[str]]:
    """Split certificate SAN entries into DNS and IP address lists."""
    dns_names: list[str] = []
    ip_addresses: list[str] = []

    if not subject_alt_names:
        return {
            "dns_names": dns_names,
            "ip_addresses": ip_addresses,
        }

    for san_type, value in subject_alt_names:
        if san_type == "DNS":
            dns_names.append(value)
        elif san_type == "IP Address":
            ip_addresses.append(value)

    return {
        "dns_names": dns_names,
        "ip_addresses": ip_addresses,
    }


def decode_der_certificate(der_certificate: bytes) -> dict[str, Any]:
    """Decode a DER certificate using standard-library SSL helpers."""
    pem_certificate = ssl.DER_cert_to_PEM_cert(der_certificate)
    temporary_path = ""

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="ascii",
            suffix=".pem",
            delete=False,
        ) as temporary_file:
            temporary_file.write(pem_certificate)
            temporary_path = temporary_file.name

        return ssl._ssl._test_decode_cert(temporary_path)
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


def build_certificate_metadata(der_certificate: bytes) -> dict[str, Any]:
    """Build JSON-ready certificate metadata from a DER certificate."""
    decoded_certificate = decode_der_certificate(der_certificate)
    subject_alt_names = split_subject_alt_names(
        decoded_certificate.get("subjectAltName")
    )

    return {
        "subject": format_certificate_name(decoded_certificate.get("subject")),
        "issuer": format_certificate_name(decoded_certificate.get("issuer")),
        "serial_number": decoded_certificate.get("serialNumber"),
        "not_before": decoded_certificate.get("notBefore"),
        "not_after": decoded_certificate.get("notAfter"),
        "version": decoded_certificate.get("version"),
        "subject_alt_names": subject_alt_names,
        "fingerprints": {
            "sha256": hashlib.sha256(der_certificate).hexdigest(),
        },
    }


def build_cipher_metadata(
    cipher_info: tuple[str, str, int] | None,
) -> dict[str, Any]:
    """Build JSON-ready TLS cipher metadata."""
    if cipher_info is None:
        return {}

    cipher_name, protocol_version, secret_bits = cipher_info
    return {
        "name": cipher_name,
        "protocol": protocol_version,
        "secret_bits": secret_bits,
    }


def grab_tls_metadata(
    client: socket.socket,
    server_hostname: str,
) -> dict[str, Any]:
    """Collect TLS handshake and certificate metadata from a connected socket."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with context.wrap_socket(
            client,
            server_hostname=server_hostname,
        ) as tls_client:
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
    except (OSError, ValueError, ssl.SSLError) as error:
        return {
            "status": "failed",
            "handshake": {},
            "certificate": {},
            "error": str(error),
        }
