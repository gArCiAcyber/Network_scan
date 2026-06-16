"""Final report panel rendering for hylianscan."""

import re
import sys
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
from modules.tls_analysis import build_tls_analysis


PANEL_SEPARATOR = f"{MUTED_GRAY}{'-' * 72}{RESET}"
HTTP_STATUS_PATTERN = re.compile(
    r"^HTTP/\S+\s+(\d{3})(?:\s+(.*?))?(?=\s+[A-Za-z][A-Za-z0-9-]*:\s|$)"
)
HTTP_HEADER_PATTERN_TEMPLATE = (
    r"(?:^|\s){header_name}:\s*(.*?)(?=\s+[A-Za-z][A-Za-z0-9-]*:\s|$)"
)


def get_triforce_symbol() -> str:
    """Return a terminal-safe Triforce symbol."""
    encoding = sys.stdout.encoding or "utf-8"
    symbol = "\u25b2"

    try:
        symbol.encode(encoding)
    except UnicodeEncodeError:
        return "^"

    return symbol


def format_panel_title() -> str:
    """Return the colored Triforce report title."""
    return (
        f"{HACKER_GREEN}[ SCAN POWERED BY THE "
        f"{BOLD_GOLD}TRIFORCE {get_triforce_symbol()}"
        f"{RESET}{HACKER_GREEN} ]{RESET}"
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


def format_display_service_name(service: str) -> str:
    """Normalize service names for terminal display."""
    normalized_service = service.lower()

    if normalized_service in {"http-alt", "https-alt"}:
        return normalized_service.replace("-alt", "")

    return normalized_service


def truncate_display_value(value: str, max_length: int = 96) -> str:
    """Keep terminal values compact and readable."""
    if len(value) <= max_length:
        return value

    return f"{value[: max_length - 3]}..."


def extract_http_header(banner: str, header_name: str) -> str | None:
    """Extract one HTTP header value from a compact banner string."""
    pattern = HTTP_HEADER_PATTERN_TEMPLATE.format(
        header_name=re.escape(header_name)
    )
    match = re.search(pattern, banner, flags=re.IGNORECASE)

    if match is None:
        return None

    value = " ".join(match.group(1).split())
    return value or None


def parse_http_status(banner: str | None) -> tuple[str, str | None] | None:
    """Return HTTP status code and reason phrase from a response banner."""
    if banner is None:
        return None

    status_match = HTTP_STATUS_PATTERN.match(banner)

    if status_match is None:
        return None

    status_code = status_match.group(1)
    reason = " ".join((status_match.group(2) or "").split()) or None
    return status_code, reason


def format_http_version_signal(banner: str | None, include_reason: bool) -> str | None:
    """Build the HTTP status and redirect signal for terminal output."""
    status = parse_http_status(banner)

    if status is None:
        return None

    status_code, reason = status
    version = status_code

    if include_reason and reason:
        version = f"{version} {reason}"

    if banner is not None:
        location = extract_http_header(banner, "Location")

        if location:
            version = f"{version} -> {truncate_display_value(location)}"

    return version


def format_tls_protocol(tls: dict[str, Any] | None) -> str | None:
    """Return the negotiated TLS protocol when available."""
    protocol = get_nested_value(tls, "handshake", "protocol")

    if isinstance(protocol, str) and protocol:
        return protocol

    return None


def format_certificate_identity(tls: dict[str, Any] | None) -> str | None:
    """Return a compact TLS certificate identity line."""
    subject_cn = get_first_text(
        get_nested_value(tls, "certificate", "subject", "commonName")
    )
    issuer = get_first_text(
        get_nested_value(tls, "certificate", "issuer", "organizationName")
    ) or get_first_text(
        get_nested_value(tls, "certificate", "issuer", "commonName")
    )

    details: list[str] = []

    if subject_cn:
        details.append(f"CN={subject_cn}")

    if issuer:
        details.append(f"Issuer={issuer}")

    if not details:
        return None

    return " | ".join(details)


def format_short_banner(banner: str | None) -> str | None:
    """Return a short non-HTTP banner for the VERSION column."""
    if not banner:
        return None

    return truncate_display_value(" ".join(banner.split()), max_length=72)


def format_final_version(finding: PortFindingView) -> str:
    """Return the main VERSION column signal for the final report."""
    http_version = format_http_version_signal(finding.banner, include_reason=True)

    if http_version:
        return http_version

    tls_protocol = format_tls_protocol(finding.tls)

    if tls_protocol:
        return tls_protocol

    short_banner = format_short_banner(finding.banner)

    if short_banner:
        return short_banner

    return "active, no banner"


def build_http_detail_lines(finding: PortFindingView) -> list[str]:
    """Build useful HTTP detail lines for the final report."""
    if finding.banner is None or parse_http_status(finding.banner) is None:
        return []

    details: list[str] = []
    server = extract_http_header(finding.banner, "Server")
    content_type = extract_http_header(finding.banner, "Content-Type")

    if server:
        details.append(f"http-server-header: {truncate_display_value(server)}")

    if content_type:
        details.append(f"http-content-type: {truncate_display_value(content_type)}")

    return details


def build_tls_detail_lines(
    finding: PortFindingView,
    target_host: str,
    include_protocol: bool,
) -> list[str]:
    """Build useful TLS detail lines for the final report."""
    if not finding.tls:
        return []

    details: list[str] = []
    protocol = format_tls_protocol(finding.tls)
    certificate_identity = format_certificate_identity(finding.tls)
    tls_analysis = build_tls_analysis(finding.tls, target_host)
    tls_severity = tls_analysis.get("severity")

    if include_protocol and protocol:
        details.append(f"tls: {protocol}")

    if certificate_identity:
        details.append(f"tls-cert: {truncate_display_value(certificate_identity)}")

    if isinstance(tls_severity, str) and tls_severity != "unknown":
        details.append(f"tls-risk: {tls_severity}")

    return details


def build_tls_reason_text_lines(
    finding: PortFindingView,
    target_host: str,
) -> list[str]:
    """Build compact saved-report TLS reason lines for one finding."""
    if not finding.tls:
        return []

    tls_analysis = build_tls_analysis(finding.tls, target_host)
    reasons = tls_analysis.get("reasons")

    if not isinstance(reasons, list) or not reasons:
        return []

    lines = [f"{finding.port}/tcp TLS risk reasons:"]

    for reason in reasons:
        if not isinstance(reason, dict):
            continue

        reason_id = reason.get("id", "unknown")
        severity = reason.get("severity", "unknown")
        title = reason.get("title", "TLS observation")
        evidence = reason.get("evidence", "No additional evidence.")
        recommendation = reason.get("recommendation", "Review TLS configuration.")
        lines.append(
            f"- {reason_id} [{severity}]: {title}. "
            f"Evidence: {evidence} Recommendation: {recommendation}"
        )

    return lines if len(lines) > 1 else []


def build_tls_reason_text_section(summary: ScanSummaryView) -> list[str]:
    """Build the saved-report TLS explanation section."""
    lines: list[str] = []

    for finding in summary.open_ports:
        reason_lines = build_tls_reason_text_lines(finding, summary.target_host)

        if reason_lines:
            if not lines:
                lines.extend(["", "TLS Risk Explanations"])
            else:
                lines.append("")

            lines.extend(reason_lines)

    return lines


def format_detail_lines(details: Sequence[str]) -> list[str]:
    """Render Nmap-style detail lines below a port row."""
    formatted_lines: list[str] = []

    for index, detail in enumerate(details):
        prefix = "|_" if index == len(details) - 1 else "| "
        formatted_lines.append(f"{MUTED_GRAY}{prefix}{detail}{RESET}")

    return formatted_lines


def build_final_panel(
    summary: ScanSummaryView,
    scan_scope: str = "Default Target List",
    scan_stance: str | None = None,
) -> str:
    """Build the final static TCP scan report."""
    lines = [
        "",
        PANEL_SEPARATOR,
        format_panel_title(),
        (
            f"{BRIGHT_WHITE}Hylianscan scan report for "
            f"{summary.target_host} ({summary.resolved_ip}){RESET}"
        ),
        f"{HACKER_GREEN}Host is up.{RESET}",
        f"{BRIGHT_WHITE}Scan Scope      :{RESET} {scan_scope}",
    ]

    lines.extend(
        [
            f"{BRIGHT_WHITE}Total Scan Time :{RESET} {summary.duration:.2f}s",
            PANEL_SEPARATOR,
            "",
        ]
    )

    if not summary.open_ports:
        lines.append(
            f"{WARNING_YELLOW}No open ports found in the {scan_scope.lower()}.{RESET}"
        )
        lines.append(PANEL_SEPARATOR)
        return "\n".join(lines)

    lines.append(f"{INFO_BLUE}{'PORT':<10} {'STATE':<6} {'SERVICE':<8} VERSION{RESET}")

    for index, finding in enumerate(summary.open_ports):
        port_label = f"{finding.port}/tcp"
        service_name = format_display_service_name(finding.service)
        version_signal = format_final_version(finding)

        if index > 0:
            lines.append("")

        lines.append(
            f"{HACKER_GREEN}{port_label:<10} "
            f"{'open':<6} "
            f"{service_name:<8} "
            f"{version_signal}{RESET}"
        )

        detail_lines = [
            *build_http_detail_lines(finding),
            *build_tls_detail_lines(
                finding,
                summary.target_host,
                include_protocol=format_http_version_signal(
                    finding.banner,
                    include_reason=True,
                ) is not None,
            ),
        ]
        lines.extend(format_detail_lines(detail_lines))

    lines.append(PANEL_SEPARATOR)
    return "\n".join(lines)


def build_saved_text_report(
    summary: ScanSummaryView,
    scan_scope: str = "Default Target List",
    scan_stance: str | None = None,
    base_report: str | None = None,
) -> str:
    """Build the TXT report, including compact TLS explanation notes."""
    report = base_report or build_final_panel(
        summary,
        scan_scope=scan_scope,
        scan_stance=scan_stance,
    )
    tls_reason_section = build_tls_reason_text_section(summary)

    if not tls_reason_section:
        return report

    return "\n".join([report, *tls_reason_section])


def build_quiet_final_panel(
    summary: ScanSummaryView,
    scan_scope: str = "Default Target List",
) -> str:
    """Build a plain automation-friendly TCP scan report."""
    lines = [
        f"Target: {summary.target_host}",
        f"Resolved IP: {summary.resolved_ip}",
        f"Scan Scope: {scan_scope}",
        f"Total Scan Time: {summary.duration:.2f}s",
    ]

    if not summary.open_ports:
        lines.append("No open ports found.")
        return "\n".join(lines)

    lines.append("Open Ports:")

    for finding in summary.open_ports:
        port_label = f"{finding.port}/tcp"
        service_name = format_display_service_name(finding.service)
        version_signal = format_final_version(finding)
        lines.append(f"- {port_label} open {service_name} {version_signal}")

    return "\n".join(lines)
