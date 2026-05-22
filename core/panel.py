"""Final report panel rendering for hylianscan."""

from collections.abc import Sequence
from typing import Protocol

from core.colors import BRIGHT_WHITE, HACKER_GREEN, INFO_BLUE, MUTED_GRAY, RESET, WARNING_YELLOW


class PortFindingView(Protocol):
    """Minimum fields required to render an open port."""

    port: int
    service: str
    banner: str | None
    response_time: float


class ScanSummaryView(Protocol):
    """Minimum fields required to render a scan summary."""

    target_host: str
    resolved_ip: str
    scanned_ports: int
    open_ports: Sequence[PortFindingView]
    duration: float


def format_open_port_line(finding: PortFindingView) -> str:
    """Format an open port discovery line."""
    service_detail = finding.banner or f"{finding.service} active (no banner)"
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
        f"{HACKER_GREEN}SCAN POWERED BY THE TRIFORCE{RESET}",
        separator,
        f"{BRIGHT_WHITE}Target Host        :{RESET} {summary.target_host}",
        f"{BRIGHT_WHITE}Resolved IP        :{RESET} {summary.resolved_ip}",
        f"{BRIGHT_WHITE}Ports Tested       :{RESET} {summary.scanned_ports}",
        f"{BRIGHT_WHITE}Open Ports         :{RESET} {len(summary.open_ports)}",
        f"{BRIGHT_WHITE}Total Scan Time    :{RESET} {summary.duration:.2f}s",
        separator,
    ]

    if summary.open_ports:
        lines.append(f"{INFO_BLUE}Port    Service   Response   Banner{RESET}")

        for finding in summary.open_ports:
            banner = finding.banner or "active (no banner)"
            lines.append(
                f"{finding.port:<7} {finding.service:<9} "
                f"{finding.response_time:.3f}s    {banner}"
            )
    else:
        lines.append(f"{WARNING_YELLOW}No open ports found in the default target list.{RESET}")

    lines.append(separator)
    return "\n".join(lines)
