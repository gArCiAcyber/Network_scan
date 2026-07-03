"""Public banner grabbing API and protocol probe dispatcher."""

import socket
from collections.abc import Callable
from typing import Any

from modules.probes.certificates import (
    build_certificate_metadata,
    build_cipher_metadata,
    decode_der_certificate,
    format_certificate_name,
    split_subject_alt_names,
)
from modules.probes.generic import (
    BANNER_SIZE,
    clean_banner,
    grab_banner,
    merge_banner_parts,
    send_probe_and_grab_banner,
)
from modules.probes.http import build_http_head_request, grab_http_banner
from modules.probes.registry import (
    FTP_PORTS,
    FTPS_PORTS,
    HTTP_PORTS,
    HTTPS_PORTS,
    IMAP_PORTS,
    POP3_PORTS,
    PROBE_METHOD_FTP_AUTH_TLS,
    PROBE_METHOD_FTP_SYST,
    PROBE_METHOD_HTTP_HEAD,
    PROBE_METHOD_IMAP_STARTTLS,
    PROBE_METHOD_PASSIVE_BANNER,
    PROBE_METHOD_POP3_STLS,
    PROBE_METHOD_SMTP_EHLO,
    PROBE_METHOD_TLS_HANDSHAKE,
    PROTOCOL_PROBE_REGISTRY,
    SMTP_PORTS,
    SMTPS_PORTS,
    TLS_BEHAVIOR_METADATA,
    TLS_BEHAVIOR_NONE,
    TLS_BEHAVIOR_PROTOCOL,
    TLS_BEHAVIOR_STARTTLS,
    TLS_BEHAVIOR_TEXT,
    TLS_METADATA_PORTS,
    TRANSPORT_SECURITY_IMPLICIT_TLS,
    TRANSPORT_SECURITY_NONE,
    TRANSPORT_SECURITY_STARTTLS,
    TRANSPORT_SECURITY_UNKNOWN,
    ProtocolProbe,
    build_probe_metadata,
    build_probe_metadata_from_definition,
    build_unknown_probe_metadata,
)
from modules.probes.starttls import (
    FTP_AUTH_TLS_PAYLOAD,
    FTP_SYST_PAYLOAD,
    IMAP_CAPABILITY_PAYLOAD,
    IMAP_STARTTLS_PAYLOAD,
    POP3_CAPA_PAYLOAD,
    POP3_STLS_PAYLOAD,
    SMTP_EHLO_PAYLOAD,
    SMTP_STARTTLS_PAYLOAD,
    build_starttls_metadata,
    build_starttls_probe_metadata,
    complete_tls_upgrade_probe,
    ftp_auth_tls_is_ready,
    grab_ftp_auth_tls_banner,
    grab_ftp_banner,
    grab_imap_starttls_banner,
    grab_pop3_stls_banner,
    grab_smtp_banner,
    grab_smtp_starttls_banner,
    imap_advertises_starttls,
    imap_starttls_is_ready,
    pop3_advertises_stls,
    pop3_stls_is_ready,
    response_contains_token,
    smtp_advertises_starttls,
    smtp_starttls_is_ready,
)
from modules.probes.tls import (
    build_tls_context,
    collect_tls_metadata,
    grab_tls_metadata,
    grab_tls_protocol_banner,
    grab_tls_text_service_banner,
)


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
