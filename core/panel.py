"""Final report panel rendering for hylianscan."""

import re
from collections.abc import Sequence
from typing import Any, Protocol

from core.colors import (
    BOLD_GOLD,
    BRIGHT_WHITE,
    HACKER_GREEN,
    INFO_BLUE,
    MUTED_GRAY,
    RESET,
    WARNING_YELLOW,
)


class PortFindingView(Protocol):
    """Minimum fields required to render an open port."""

    port: int
    service: str
    banner: str | None
    response_time: float
    web_url: str | None
    tls: dict[str, Any] | None


class ScanSummaryView(Protocol):
    """Minimum fields required to render a scan summary."""

    target_host: str
    resolved_ip: str
    scanned_ports: int
    open_ports: Sequence[PortFindingView]
    duration: float


def get_nested_value(data: dict[str, Any] | None, *keys: str) -> Any:
    """Read a nested metadata value without assuming every field exists."""
    current: Any = data

    for key in keys:
        if not isinstance(current, dict):
            return None

        current = current.get(key)

    return current


def get_first_text(value: Any) -> str | None:
    """Return the first useful text value from a scalar or list field."""
    if isinstance(value, str) and value:
        return value

    if isinstance(value, list) and value:
        first_value = value[0]

        if isinstance(first_value, str) and first_value:
            return first_value

    return None


def format_tls_summary(tls: dict[str, Any] | None) -> str | None:
    """Build a compact terminal summary for collected TLS metadata."""
    if not tls:
        return None

    status = tls.get("status")

    if status not in {"collected", "no_certificate"}:
        return None

    protocol = get_nested_value(tls, "handshake", "protocol")
    cipher_name = get_nested_value(tls, "handshake", "cipher", "name")
    subject_cn = get_first_text(
        get_nested_value(tls, "certificate", "subject", "commonName")
    )
    issuer = get_first_text(
        get_nested_value(tls, "certificate", "issuer", "organizationName")
    ) or get_first_text(
        get_nested_value(tls, "certificate", "issuer", "commonName")
    )

    details: list[str] = []

    if isinstance(protocol, str) and protocol:
        details.append(protocol)

    if subject_cn:
        details.append(f"CN={subject_cn}")

    if issuer:
        details.append(f"Issuer={issuer}")

    if not issuer and isinstance(cipher_name, str) and cipher_name:
        details.append(f"Cipher={cipher_name}")

    if status == "no_certificate":
        details.append("no certificate")

    if not details:
        return None

    return f"TLS {' | '.join(details)}"


def truncate_display_value(value: str, max_length: int = 80) -> str:
    """Keep terminal header values compact and readable."""
    if len(value) <= max_length:
        return value

    return f"{value[: max_length - 3]}..."


def extract_http_header(banner: str, header_name: str) -> str | None:
    """Extract one HTTP header value from a compact banner string."""
    pattern = (
        rf"(?:^|\s){re.escape(header_name)}:\s*"
        r"(.*?)(?=\s+[A-Za-z][A-Za-z0-9-]*:\s|$)"
    )
    match = re.search(pattern, banner, flags=re.IGNORECASE)

    if match is None:
        return None

    value = " ".join(match.group(1).split())
    return value or None


def format_http_summary(banner: str | None) -> str | None:
    """Build a compact terminal summary from an HTTP response banner."""
    if not banner:
        return None

    status_match = re.match(
        r"^HTTP/\S+\s+(\d{3})(?:\s+(.*?))?(?=\s+[A-Za-z][A-Za-z0-9-]*:\s|$)",
        banner,
    )

    if status_match is None:
        return None

    status_code = status_match.group(1)
    reason = " ".join((status_match.group(2) or "").split())
    status = f"HTTP {status_code}"

    if reason:
        status = f"{status} {reason}"

    details = [status]

    for header_name, label in (
        ("Server", "Server"),
        ("Location", "Location"),
        ("Content-Type", "Content-Type"),
    ):
        value = extract_http_header(banner, header_name)

        if value:
            details.append(f"{label}={truncate_display_value(value)}")

    return " | ".join(details)


def format_service_detail(finding: PortFindingView, include_web_url: bool) -> str:
    """Return the most useful terminal service detail for a finding."""
    service_detail = (
        format_http_summary(finding.banner)
        or finding.banner
        or format_tls_summary(finding.tls)
        or f"{finding.service} active (no banner)"
    )

    if include_web_url and finding.banner is None and finding.web_url is not None:
        service_detail = f"{service_detail} | {finding.web_url}"

    return service_detail


def format_open_port_line(finding: PortFindingView) -> str:
    """Format an open port discovery line."""
    service_detail = format_service_detail(finding, include_web_url=True)

    return (
        f"{HACKER_GREEN}[+] Port {finding.port:<5} [OPEN] "
        f"-> Service: {service_detail}{RESET}"
    )


def build_final_panel(summary: ScanSummaryView) -> str:
    """Build the final static scan report panel."""
    separator = f"{MUTED_GRAY}{'-' * 72}{RESET}"
    lines = [
        "",
        separator,
        # User's custom style: HACKER_GREEN for the bracket/text and Bold Gold for THE TRIFORCE
        f"{HACKER_GREEN}[ SCAN POWERED BY THE {BOLD_GOLD}TRIFORCE ▲{RESET}{HACKER_GREEN} ]{RESET}",
        separator,
        f"{BRIGHT_WHITE}Target Host        :{RESET} {summary.target_host}",
        f"{BRIGHT_WHITE}Resolved IP        :{RESET} {summary.resolved_ip}",
        f"{BRIGHT_WHITE}Scan Scope         :{RESET} Default Target List",
        f"{BRIGHT_WHITE}Total Scan Time    :{RESET} {summary.duration:.2f}s",
        separator,
    ]

    if summary.open_ports:
        lines.append(f"{INFO_BLUE}Port    Status     Service    Version / Banner{RESET}")
        for finding in summary.open_ports:
            banner = format_service_detail(finding, include_web_url=False)
            clean_service = finding.service.lower()

            lines.append(
                f"{HACKER_GREEN}{finding.port:<7} "
                f"[OPEN]     "
                f"{clean_service:<10} "
                f"{banner}{RESET}"
            )
    else:
        lines.append(f"{WARNING_YELLOW}No open ports found in the default target list.{RESET}")

    lines.append(separator)
    return "\n".join(lines)
