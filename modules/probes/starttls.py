"""STARTTLS-style text protocol probes."""

import socket
import ssl
from typing import Any

from modules.probes.generic import (
    grab_banner,
    merge_banner_parts,
    send_probe_and_grab_banner,
)
from modules.probes.registry import (
    PROBE_METHOD_FTP_AUTH_TLS,
    PROBE_METHOD_FTP_SYST,
    PROBE_METHOD_IMAP_STARTTLS,
    PROBE_METHOD_POP3_STLS,
    PROBE_METHOD_SMTP_EHLO,
    TRANSPORT_SECURITY_NONE,
    TRANSPORT_SECURITY_STARTTLS,
    build_probe_metadata,
)
from modules.probes.tls import build_tls_context, collect_tls_metadata


SMTP_EHLO_PAYLOAD = b"EHLO hylianscan.local\r\n"
SMTP_STARTTLS_PAYLOAD = b"STARTTLS\r\n"
IMAP_CAPABILITY_PAYLOAD = b"a001 CAPABILITY\r\n"
IMAP_STARTTLS_PAYLOAD = b"a002 STARTTLS\r\n"
POP3_CAPA_PAYLOAD = b"CAPA\r\n"
POP3_STLS_PAYLOAD = b"STLS\r\n"
FTP_AUTH_TLS_PAYLOAD = b"AUTH TLS\r\n"
FTP_SYST_PAYLOAD = b"SYST\r\n"


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


def build_starttls_metadata(supported: bool) -> dict[str, Any]:
    """Build reusable TLS upgrade metadata for plaintext protocols."""
    return {
        "supported": supported,
        "attempted": False,
        "upgraded": False,
        "error": None,
    }


def build_starttls_probe_metadata(
    protocol_name: str,
    transport_security: str,
    method: str,
    starttls: dict[str, Any],
) -> dict[str, Any]:
    """Build probe metadata for STARTTLS-style upgrade attempts."""
    return build_probe_metadata(
        name=protocol_name,
        transport_security=transport_security,
        method=method,
        starttls=starttls,
    )


def complete_tls_upgrade_probe(
    client: socket.socket,
    server_hostname: str,
    protocol_name: str,
    method: str,
    banner: str | None,
    starttls: dict[str, Any],
) -> tuple[str | None, dict[str, Any] | None, dict[str, Any]]:
    """Wrap an upgraded plaintext socket and collect TLS metadata."""
    context = build_tls_context()

    try:
        with context.wrap_socket(
            client,
            server_hostname=server_hostname,
        ) as tls_client:
            starttls["upgraded"] = True
            return (
                banner,
                collect_tls_metadata(tls_client),
                build_starttls_probe_metadata(
                    protocol_name,
                    TRANSPORT_SECURITY_STARTTLS,
                    method,
                    starttls,
                ),
            )
    except (OSError, ValueError, ssl.SSLError) as error:
        starttls["error"] = str(error)
        return (
            banner,
            None,
            build_starttls_probe_metadata(
                protocol_name,
                TRANSPORT_SECURITY_NONE,
                method,
                starttls,
            ),
        )


def grab_smtp_starttls_banner(
    client: socket.socket,
    server_hostname: str,
) -> tuple[str | None, dict[str, Any] | None, dict[str, Any]]:
    """Collect SMTP evidence and upgrade to TLS when STARTTLS is available."""
    greeting = grab_banner(client)
    ehlo_response = send_probe_and_grab_banner(client, SMTP_EHLO_PAYLOAD)
    plain_banner = merge_banner_parts(greeting, ehlo_response)
    starttls_metadata = build_starttls_metadata(
        supported=smtp_advertises_starttls(ehlo_response)
    )

    if not starttls_metadata["supported"]:
        return (
            plain_banner,
            None,
            build_starttls_probe_metadata(
                "smtp",
                TRANSPORT_SECURITY_NONE,
                PROBE_METHOD_SMTP_EHLO,
                starttls_metadata,
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
            build_starttls_probe_metadata(
                "smtp",
                TRANSPORT_SECURITY_NONE,
                PROBE_METHOD_SMTP_EHLO,
                starttls_metadata,
            ),
        )

    return complete_tls_upgrade_probe(
        client,
        server_hostname,
        "smtp",
        PROBE_METHOD_SMTP_EHLO,
        starttls_banner,
        starttls_metadata,
    )


def response_contains_token(response: str | None, token: str) -> bool:
    """Return True when a compact protocol response contains a standalone token."""
    if not response:
        return False

    normalized_response = f" {response.upper()} "
    normalized_token = f" {token.upper()} "
    return normalized_token in normalized_response


def imap_advertises_starttls(capability_response: str | None) -> bool:
    """Return True when IMAP capabilities advertise STARTTLS."""
    return response_contains_token(capability_response, "STARTTLS")


def imap_starttls_is_ready(response: str | None) -> bool:
    """Return True when IMAP accepts STARTTLS negotiation."""
    if not response:
        return False

    normalized_response = response.upper()
    return normalized_response.startswith("A002 OK") or " A002 OK " in f" {normalized_response} "


def pop3_advertises_stls(capability_response: str | None) -> bool:
    """Return True when POP3 capabilities advertise STLS."""
    return response_contains_token(capability_response, "STLS")


def pop3_stls_is_ready(response: str | None) -> bool:
    """Return True when POP3 accepts STLS negotiation."""
    return bool(response and response.upper().startswith("+OK"))


def ftp_auth_tls_is_ready(response: str | None) -> bool:
    """Return True when FTP accepts AUTH TLS negotiation."""
    return bool(response and response[:1] == "2")


def grab_imap_starttls_banner(
    client: socket.socket,
    server_hostname: str,
) -> tuple[str | None, dict[str, Any] | None, dict[str, Any]]:
    """Collect IMAP capabilities and upgrade to TLS when STARTTLS is available."""
    greeting = grab_banner(client)
    capability_response = send_probe_and_grab_banner(client, IMAP_CAPABILITY_PAYLOAD)
    plain_banner = merge_banner_parts(greeting, capability_response)
    starttls_metadata = build_starttls_metadata(
        supported=imap_advertises_starttls(capability_response)
    )

    if not starttls_metadata["supported"]:
        return (
            plain_banner,
            None,
            build_starttls_probe_metadata(
                "imap",
                TRANSPORT_SECURITY_NONE,
                PROBE_METHOD_IMAP_STARTTLS,
                starttls_metadata,
            ),
        )

    starttls_metadata["attempted"] = True
    starttls_response = send_probe_and_grab_banner(client, IMAP_STARTTLS_PAYLOAD)
    starttls_banner = merge_banner_parts(plain_banner, starttls_response)

    if not imap_starttls_is_ready(starttls_response):
        starttls_metadata["error"] = (
            "STARTTLS was advertised but the server did not return a tagged OK response."
        )
        return (
            starttls_banner,
            None,
            build_starttls_probe_metadata(
                "imap",
                TRANSPORT_SECURITY_NONE,
                PROBE_METHOD_IMAP_STARTTLS,
                starttls_metadata,
            ),
        )

    return complete_tls_upgrade_probe(
        client,
        server_hostname,
        "imap",
        PROBE_METHOD_IMAP_STARTTLS,
        starttls_banner,
        starttls_metadata,
    )


def grab_pop3_stls_banner(
    client: socket.socket,
    server_hostname: str,
) -> tuple[str | None, dict[str, Any] | None, dict[str, Any]]:
    """Collect POP3 capabilities and upgrade to TLS when STLS is available."""
    greeting = grab_banner(client)
    capability_response = send_probe_and_grab_banner(client, POP3_CAPA_PAYLOAD)
    plain_banner = merge_banner_parts(greeting, capability_response)
    starttls_metadata = build_starttls_metadata(
        supported=pop3_advertises_stls(capability_response)
    )

    if not starttls_metadata["supported"]:
        return (
            plain_banner,
            None,
            build_starttls_probe_metadata(
                "pop3",
                TRANSPORT_SECURITY_NONE,
                PROBE_METHOD_POP3_STLS,
                starttls_metadata,
            ),
        )

    starttls_metadata["attempted"] = True
    stls_response = send_probe_and_grab_banner(client, POP3_STLS_PAYLOAD)
    stls_banner = merge_banner_parts(plain_banner, stls_response)

    if not pop3_stls_is_ready(stls_response):
        starttls_metadata["error"] = (
            "STLS was advertised but the server did not return a +OK response."
        )
        return (
            stls_banner,
            None,
            build_starttls_probe_metadata(
                "pop3",
                TRANSPORT_SECURITY_NONE,
                PROBE_METHOD_POP3_STLS,
                starttls_metadata,
            ),
        )

    return complete_tls_upgrade_probe(
        client,
        server_hostname,
        "pop3",
        PROBE_METHOD_POP3_STLS,
        stls_banner,
        starttls_metadata,
    )


def grab_ftp_auth_tls_banner(
    client: socket.socket,
    server_hostname: str,
) -> tuple[str | None, dict[str, Any] | None, dict[str, Any]]:
    """Collect FTP greeting and upgrade to TLS when AUTH TLS is accepted."""
    greeting = grab_banner(client)
    starttls_metadata = build_starttls_metadata(supported=False)
    starttls_metadata["attempted"] = True
    auth_tls_response = send_probe_and_grab_banner(client, FTP_AUTH_TLS_PAYLOAD)
    starttls_metadata["supported"] = ftp_auth_tls_is_ready(auth_tls_response)
    auth_tls_banner = merge_banner_parts(greeting, auth_tls_response)

    if not starttls_metadata["supported"]:
        starttls_metadata["error"] = (
            "AUTH TLS was not accepted by the FTP service."
        )
        system_response = send_probe_and_grab_banner(client, FTP_SYST_PAYLOAD)
        plain_banner = merge_banner_parts(auth_tls_banner, system_response)
        return (
            plain_banner,
            None,
            build_starttls_probe_metadata(
                "ftp",
                TRANSPORT_SECURITY_NONE,
                PROBE_METHOD_FTP_AUTH_TLS,
                starttls_metadata,
            ),
        )

    return complete_tls_upgrade_probe(
        client,
        server_hostname,
        "ftp",
        PROBE_METHOD_FTP_AUTH_TLS,
        auth_tls_banner,
        starttls_metadata,
    )


def grab_ftp_banner(client: socket.socket) -> str | None:
    """Collect FTP greeting and basic system metadata."""
    greeting = grab_banner(client)
    system_response = send_probe_and_grab_banner(client, FTP_SYST_PAYLOAD)
    return merge_banner_parts(greeting, system_response)
