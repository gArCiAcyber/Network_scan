"""TCP banner grabbing helpers for hylianscan."""

import hashlib
import os
import socket
import ssl
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


BANNER_SIZE = 1024
HTTP_PORTS = {
    80,
    2052,
    2082,
    2086,
    2095,
    8000,
    8008,
    8080,
    8081,
    8088,
    8090,
    8880,
    8888,
}
HTTPS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
SMTP_PORTS = {25, 587}
SMTPS_PORTS = {465}
FTP_PORTS = {21, 2121}
FTPS_PORTS = {990}
TLS_METADATA_PORTS = {443, 465, 636, 2053, 2083, 2087, 2096, 8443, 989, 990, 993, 995}
TLS_BEHAVIOR_NONE = "none"
TLS_BEHAVIOR_PROTOCOL = "protocol"
TLS_BEHAVIOR_TEXT = "text"
TLS_BEHAVIOR_METADATA = "metadata"
TLS_BEHAVIOR_STARTTLS = "starttls"
TRANSPORT_SECURITY_NONE = "none"
TRANSPORT_SECURITY_IMPLICIT_TLS = "implicit_tls"
TRANSPORT_SECURITY_STARTTLS = "starttls"
TRANSPORT_SECURITY_UNKNOWN = "unknown"
PROBE_METHOD_HTTP_HEAD = "http_head"
PROBE_METHOD_SMTP_EHLO = "smtp_ehlo"
PROBE_METHOD_FTP_SYST = "ftp_syst"
PROBE_METHOD_TLS_HANDSHAKE = "tls_handshake"
PROBE_METHOD_PASSIVE_BANNER = "passive_banner"
SMTP_EHLO_PAYLOAD = b"EHLO hylianscan.local\r\n"
SMTP_STARTTLS_PAYLOAD = b"STARTTLS\r\n"


@dataclass(frozen=True)
class ProtocolProbe:
    """Describes how to collect service evidence for one protocol family."""

    protocol_name: str
    ports: frozenset[int]
    handler_name: str
    tls_behavior: str = TLS_BEHAVIOR_NONE
    probe_payload: bytes | None = None
    use_http_head_request: bool = False
    requires_target_host: bool = False
    transport_security: str = TRANSPORT_SECURITY_NONE
    probe_method: str = PROBE_METHOD_PASSIVE_BANNER


PROTOCOL_PROBE_REGISTRY = (
    ProtocolProbe(
        protocol_name="https",
        ports=frozenset(HTTPS_PORTS),
        handler_name="grab_tls_protocol_banner",
        tls_behavior=TLS_BEHAVIOR_PROTOCOL,
        use_http_head_request=True,
        transport_security=TRANSPORT_SECURITY_IMPLICIT_TLS,
        probe_method=PROBE_METHOD_HTTP_HEAD,
    ),
    ProtocolProbe(
        protocol_name="http",
        ports=frozenset(HTTP_PORTS),
        handler_name="grab_http_banner",
        requires_target_host=True,
        probe_method=PROBE_METHOD_HTTP_HEAD,
    ),
    ProtocolProbe(
        protocol_name="smtp",
        ports=frozenset(SMTP_PORTS),
        handler_name="grab_smtp_starttls_banner",
        tls_behavior=TLS_BEHAVIOR_STARTTLS,
        probe_method=PROBE_METHOD_SMTP_EHLO,
    ),
    ProtocolProbe(
        protocol_name="smtps",
        ports=frozenset(SMTPS_PORTS),
        handler_name="grab_tls_text_service_banner",
        tls_behavior=TLS_BEHAVIOR_TEXT,
        probe_payload=b"EHLO hylianscan.local\r\n",
        transport_security=TRANSPORT_SECURITY_IMPLICIT_TLS,
        probe_method=PROBE_METHOD_SMTP_EHLO,
    ),
    ProtocolProbe(
        protocol_name="ftp",
        ports=frozenset(FTP_PORTS),
        handler_name="grab_ftp_banner",
        probe_method=PROBE_METHOD_FTP_SYST,
    ),
    ProtocolProbe(
        protocol_name="ftps",
        ports=frozenset(FTPS_PORTS),
        handler_name="grab_tls_text_service_banner",
        tls_behavior=TLS_BEHAVIOR_TEXT,
        probe_payload=b"SYST\r\n",
        transport_security=TRANSPORT_SECURITY_IMPLICIT_TLS,
        probe_method=PROBE_METHOD_FTP_SYST,
    ),
    ProtocolProbe(
        protocol_name="generic_tls_metadata",
        ports=frozenset(TLS_METADATA_PORTS),
        handler_name="grab_tls_metadata",
        tls_behavior=TLS_BEHAVIOR_METADATA,
        transport_security=TRANSPORT_SECURITY_IMPLICIT_TLS,
        probe_method=PROBE_METHOD_TLS_HANDSHAKE,
    ),
)


def build_probe_metadata(
    name: str,
    transport_security: str,
    method: str,
    starttls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build structured JSON-ready probe metadata."""
    metadata: dict[str, Any] = {
        "name": name,
        "transport_security": transport_security,
        "method": method,
    }

    if starttls is not None:
        metadata["starttls"] = starttls

    return metadata


def build_probe_metadata_from_definition(
    probe: ProtocolProbe,
    transport_security: str | None = None,
    starttls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build probe metadata from a registered probe definition."""
    return build_probe_metadata(
        name=probe.protocol_name,
        transport_security=transport_security or probe.transport_security,
        method=probe.probe_method,
        starttls=starttls,
    )


def build_unknown_probe_metadata() -> dict[str, Any]:
    """Build probe metadata for unknown passive banner fallback."""
    return build_probe_metadata(
        name="unknown",
        transport_security=TRANSPORT_SECURITY_UNKNOWN,
        method=PROBE_METHOD_PASSIVE_BANNER,
    )


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


def grab_smtp_banner(client: socket.socket) -> str | None:
    """Collect SMTP greeting and advertised capabilities."""
    greeting = grab_banner(client)
    ehlo_response = send_probe_and_grab_banner(client, SMTP_EHLO_PAYLOAD)
    return merge_banner_parts(greeting, ehlo_response)


def smtp_advertises_starttls(ehlo_response: str | None) -> bool:
    """Return True when SMTP capabilities advertise STARTTLS."""
    if not ehlo_response:
        return False

    return "STARTTLS" in ehlo_response.upper()


def smtp_starttls_is_ready(response: str | None) -> bool:
    """Return True when SMTP accepts STARTTLS negotiation."""
    return bool(response and response.startswith("220"))


def grab_smtp_starttls_banner(
    client: socket.socket,
    server_hostname: str,
) -> tuple[str | None, dict[str, Any] | None, dict[str, Any]]:
    """Collect SMTP evidence and upgrade to TLS when STARTTLS is available."""
    greeting = grab_banner(client)
    ehlo_response = send_probe_and_grab_banner(client, SMTP_EHLO_PAYLOAD)
    plain_banner = merge_banner_parts(greeting, ehlo_response)
    starttls_metadata: dict[str, Any] = {
        "supported": smtp_advertises_starttls(ehlo_response),
        "attempted": False,
        "upgraded": False,
        "error": None,
    }

    if not starttls_metadata["supported"]:
        return (
            plain_banner,
            None,
            build_probe_metadata(
                name="smtp",
                transport_security=TRANSPORT_SECURITY_NONE,
                method=PROBE_METHOD_SMTP_EHLO,
                starttls=starttls_metadata,
            ),
        )

    starttls_metadata["attempted"] = True
    starttls_response = send_probe_and_grab_banner(client, SMTP_STARTTLS_PAYLOAD)
    starttls_banner = merge_banner_parts(plain_banner, starttls_response)

    if not smtp_starttls_is_ready(starttls_response):
        starttls_metadata["error"] = (
            "STARTTLS was advertised but the server did not return a 220 ready response."
        )
        return (
            starttls_banner,
            None,
            build_probe_metadata(
                name="smtp",
                transport_security=TRANSPORT_SECURITY_NONE,
                method=PROBE_METHOD_SMTP_EHLO,
                starttls=starttls_metadata,
            ),
        )

    context = build_tls_context()

    try:
        with context.wrap_socket(
            client,
            server_hostname=server_hostname,
        ) as tls_client:
            starttls_metadata["upgraded"] = True
            return (
                starttls_banner,
                collect_tls_metadata(tls_client),
                build_probe_metadata(
                    name="smtp",
                    transport_security=TRANSPORT_SECURITY_STARTTLS,
                    method=PROBE_METHOD_SMTP_EHLO,
                    starttls=starttls_metadata,
                ),
            )
    except (OSError, ValueError, ssl.SSLError) as error:
        starttls_metadata["error"] = str(error)
        return (
            starttls_banner,
            None,
            build_probe_metadata(
                name="smtp",
                transport_security=TRANSPORT_SECURITY_NONE,
                method=PROBE_METHOD_SMTP_EHLO,
                starttls=starttls_metadata,
            ),
        )


def grab_ftp_banner(client: socket.socket) -> str | None:
    """Collect FTP greeting and basic system metadata."""
    greeting = grab_banner(client)
    system_response = send_probe_and_grab_banner(client, b"SYST\r\n")
    return merge_banner_parts(greeting, system_response)


def should_collect_tls_metadata(port: int) -> bool:
    """Return True when a TCP port is expected to expose TLS metadata."""
    return port in TLS_METADATA_PORTS


def find_probe_definition(port: int) -> ProtocolProbe | None:
    """Return the first registered protocol probe for a TCP port."""
    for probe in PROTOCOL_PROBE_REGISTRY:
        if port in probe.ports:
            return probe

    return None


def get_probe_handler(handler_name: str) -> Callable[..., Any]:
    """Resolve a probe handler dynamically for testable dispatch."""
    handler = globals()[handler_name]

    if not callable(handler):
        raise TypeError(f"Probe handler is not callable: {handler_name}")

    return handler


def resolve_probe_payload(
    probe: ProtocolProbe,
    target_host: str,
) -> bytes | None:
    """Return the probe payload for a protocol definition."""
    if probe.use_http_head_request:
        return build_http_head_request(target_host)

    return probe.probe_payload


def build_tls_context() -> ssl.SSLContext:
    """Create a TLS context for metadata collection without trust enforcement."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


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


def grab_service_banner(
    client: socket.socket,
    target_host: str,
    port: int,
) -> tuple[str | None, dict[str, Any] | None, dict[str, Any]]:
    """Collect the best available banner and optional TLS metadata for a service."""
    probe = find_probe_definition(port)

    if probe is None:
        return grab_banner(client), None, build_unknown_probe_metadata()

    handler = get_probe_handler(probe.handler_name)
    payload = resolve_probe_payload(probe, target_host)

    if probe.tls_behavior == TLS_BEHAVIOR_PROTOCOL:
        banner, tls_metadata = handler(client, target_host, payload)
        return banner, tls_metadata, build_probe_metadata_from_definition(probe)

    if probe.tls_behavior == TLS_BEHAVIOR_TEXT:
        if payload is None:
            return (
                None,
                grab_tls_metadata(client, target_host),
                build_probe_metadata_from_definition(probe),
            )

        banner, tls_metadata = handler(client, target_host, payload)
        return banner, tls_metadata, build_probe_metadata_from_definition(probe)

    if probe.tls_behavior == TLS_BEHAVIOR_METADATA:
        return (
            None,
            handler(client, target_host),
            build_probe_metadata_from_definition(probe),
        )

    if probe.tls_behavior == TLS_BEHAVIOR_STARTTLS:
        return handler(client, target_host)

    if payload is not None:
        return (
            send_probe_and_grab_banner(client, payload),
            None,
            build_probe_metadata_from_definition(probe),
        )

    if probe.requires_target_host:
        return (
            handler(client, target_host),
            None,
            build_probe_metadata_from_definition(probe),
        )

    return handler(client), None, build_probe_metadata_from_definition(probe)
