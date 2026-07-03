"""TLS certificate metadata helpers."""

import hashlib
import os
import ssl
import tempfile
from typing import Any


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
