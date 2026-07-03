"""Protocol probe registry and metadata helpers."""

from dataclasses import dataclass
from typing import Any


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
IMAP_PORTS = {143}
POP3_PORTS = {110}
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
PROBE_METHOD_IMAP_STARTTLS = "imap_starttls"
PROBE_METHOD_POP3_STLS = "pop3_stls"
PROBE_METHOD_FTP_AUTH_TLS = "ftp_auth_tls"
PROBE_METHOD_FTP_SYST = "ftp_syst"
PROBE_METHOD_TLS_HANDSHAKE = "tls_handshake"
PROBE_METHOD_PASSIVE_BANNER = "passive_banner"


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
        protocol_name="imap",
        ports=frozenset(IMAP_PORTS),
        handler_name="grab_imap_starttls_banner",
        tls_behavior=TLS_BEHAVIOR_STARTTLS,
        probe_method=PROBE_METHOD_IMAP_STARTTLS,
    ),
    ProtocolProbe(
        protocol_name="pop3",
        ports=frozenset(POP3_PORTS),
        handler_name="grab_pop3_stls_banner",
        tls_behavior=TLS_BEHAVIOR_STARTTLS,
        probe_method=PROBE_METHOD_POP3_STLS,
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
        handler_name="grab_ftp_auth_tls_banner",
        tls_behavior=TLS_BEHAVIOR_STARTTLS,
        probe_method=PROBE_METHOD_FTP_AUTH_TLS,
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
