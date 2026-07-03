"""Protocol registry patch helpers for localhost mock-service tests."""

from collections.abc import Iterator
from unittest.mock import patch

from modules import banner_grabber


def patched_tls_registry(port: int) -> Iterator[object]:
    """Patch protocol probing so the ephemeral port is treated as TLS."""
    tls_probe = banner_grabber.ProtocolProbe(
        protocol_name="generic_tls_metadata",
        ports=frozenset({port}),
        handler_name="grab_tls_metadata",
        tls_behavior=banner_grabber.TLS_BEHAVIOR_METADATA,
    )

    return patch("modules.banner_grabber.PROTOCOL_PROBE_REGISTRY", (tls_probe,))


def patched_smtp_starttls_registry(port: int) -> Iterator[object]:
    """Patch protocol probing so the ephemeral port is treated as SMTP STARTTLS."""
    smtp_probe = banner_grabber.ProtocolProbe(
        protocol_name="smtp",
        ports=frozenset({port}),
        handler_name="grab_smtp_starttls_banner",
        tls_behavior=banner_grabber.TLS_BEHAVIOR_STARTTLS,
    )

    return patch("modules.banner_grabber.PROTOCOL_PROBE_REGISTRY", (smtp_probe,))


def patched_imap_starttls_registry(port: int) -> Iterator[object]:
    """Patch protocol probing so the ephemeral port is treated as IMAP STARTTLS."""
    imap_probe = banner_grabber.ProtocolProbe(
        protocol_name="imap",
        ports=frozenset({port}),
        handler_name="grab_imap_starttls_banner",
        tls_behavior=banner_grabber.TLS_BEHAVIOR_STARTTLS,
    )

    return patch("modules.banner_grabber.PROTOCOL_PROBE_REGISTRY", (imap_probe,))


def patched_pop3_stls_registry(port: int) -> Iterator[object]:
    """Patch protocol probing so the ephemeral port is treated as POP3 STLS."""
    pop3_probe = banner_grabber.ProtocolProbe(
        protocol_name="pop3",
        ports=frozenset({port}),
        handler_name="grab_pop3_stls_banner",
        tls_behavior=banner_grabber.TLS_BEHAVIOR_STARTTLS,
    )

    return patch("modules.banner_grabber.PROTOCOL_PROBE_REGISTRY", (pop3_probe,))


def patched_ftp_auth_tls_registry(port: int) -> Iterator[object]:
    """Patch protocol probing so the ephemeral port is treated as FTP AUTH TLS."""
    ftp_probe = banner_grabber.ProtocolProbe(
        protocol_name="ftp",
        ports=frozenset({port}),
        handler_name="grab_ftp_auth_tls_banner",
        tls_behavior=banner_grabber.TLS_BEHAVIOR_STARTTLS,
    )

    return patch("modules.banner_grabber.PROTOCOL_PROBE_REGISTRY", (ftp_probe,))
