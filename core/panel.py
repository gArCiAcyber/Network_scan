"""Final report panel rendering for hylianscan."""

from collections.abc import Sequence
from typing import Protocol

# Added BOLD_GOLD to the imports
from core.colors import BOLD_GOLD, BRIGHT_WHITE, HACKER_GREEN, INFO_BLUE, MUTED_GRAY, RESET, WARNING_YELLOW


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
            banner = finding.banner or "active (no banner)"
            
            # Clean and lowercase the service name (e.g., "HTTP | http://..." becomes "http")
            raw_service = finding.service.split(" | ")[0] if " | " in finding.service else finding.service
            clean_service = raw_service.lower()
            
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