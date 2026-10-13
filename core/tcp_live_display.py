"""Live TCP scan rendering helpers for hylianscan."""

import shutil
import sys
import time

from core.colors import BRIGHT_WHITE, GREEN, MUTED_GRAY, RESET
from core.terminal import clear_dynamic_line, escape_controls, print_safe, wrap_report, write_dynamic_line
from modules.target import TargetInfo
from modules.tcp_scanner import PortScanResult


PROGRESS_BAR_WIDTH = 20
PROGRESS_REFRESH_SECONDS = 0.1


def format_duration(seconds: float) -> str:
    """Return a compact estimated duration."""
    normalized_seconds = max(0, int(round(seconds)))
    hours, remainder = divmod(normalized_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{seconds:02d}"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


def clamp_progress(progress: float) -> float:
    """Clamp progress into the terminal progress-bar range."""
    return max(0.0, min(1.0, progress))


def supports_sword_symbols() -> bool:
    """Check every decorative symbol before choosing the Unicode sword."""
    encoding = sys.stdout.encoding or "utf-8"

    try:
        "\u25c8\u256c\u2501\u2500\u25b7\u00b7".encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return False

    return True


def render_sword_progress_bar(progress: float, width: int = PROGRESS_BAR_WIDTH) -> str:
    """Render a bright green blade with a muted, unfilled track."""
    safe_progress = clamp_progress(progress)
    safe_width = max(1, width)
    filled_count = round(safe_progress * safe_width)
    hilt, filled, empty, tip = (
        ("\u25c8\u256c[", "\u2501", "\u2500", "]\u25b7")
        if supports_sword_symbols() else ("o+[", "#", "-", "]>")
    )
    return (
        f"{GREEN}{hilt}{filled * filled_count}"
        f"{MUTED_GRAY}{empty * (safe_width - filled_count)}"
        f"{GREEN}{tip}{RESET}"
    )


class TCPScanDisplay:
    """Render phase-oriented TCP scan activity."""

    def __init__(self, target: TargetInfo, port_count: int) -> None:
        self.target = target
        self.port_count = port_count
        self.connect_started_at = time.monotonic()
        self._last_refresh: float | None = None

    def start_connect_scan(self) -> None:
        """Identify the native discovery phase and start its timing."""
        self.connect_started_at = time.monotonic()
        self._last_refresh = None
        print_safe(f"{BRIGHT_WHITE}[*] Native TCP Discovery{RESET}")

    def stop(self) -> None:
        """Clear live progress before permanent output or scan exit."""
        clear_dynamic_line()

    def handle_progress(self, completed: int, total: int, _port: int) -> None:
        """Render dynamic TCP connect scan timing."""
        if completed <= 0 or total <= 0:
            return

        now = time.monotonic()
        if completed < total and self._last_refresh is not None and now - self._last_refresh < PROGRESS_REFRESH_SECONDS:
            return
        self._last_refresh = now
        elapsed_seconds = max(0.0, now - self.connect_started_at)
        progress = clamp_progress(completed / total)
        percent_done = min(100, completed * 100 // total)
        estimated_total = elapsed_seconds / completed * total
        remaining_seconds = max(0.0, estimated_total - elapsed_seconds)
        # Leave a spare column so progress never wraps into another terminal row.
        width = max(1, shutil.get_terminal_size(fallback=(100, 24)).columns - 1)
        unit = " ports" if total == self.port_count else ""
        separator = "\u00b7" if supports_sword_symbols() else "|"
        completed_text = f"{completed:,}".rjust(len(f"{total:,}"))
        counts = f"{completed_text} / {total:,}{unit}"
        eta = f"~{format_duration(remaining_seconds)} left"
        label = "TCP scan about : "
        # Shorten secondary details first; retain the phase and percentage.
        for details in (f"{counts} {separator} {eta}", f"{completed_text}/{total:,} {separator} {eta}", eta, ""):
            suffix = f"  {percent_done:3d}%" + (f" {separator} {details}" if details else "")
            blade_width = min(PROGRESS_BAR_WIDTH, width - len(label) - 5 - len(suffix))
            if blade_width >= 4:
                write_dynamic_line(f"{label}{render_sword_progress_bar(progress, blade_width)}{suffix}")
                return
        label = label if width >= len(label) + 4 else "TCP "
        write_dynamic_line(f"{label}{percent_done:3d}%"[:width])

    def handle_open_port(self, result: PortScanResult) -> None:
        """Render a permanent open-port discovery line."""
        self.stop()
        address_suffix = ""

        if len(self.target.address_records) > 1 and result.address:
            family_label = {"ipv4": "IPv4", "ipv6": "IPv6"}.get(
                result.address_family,
                result.address_family,
            )
            family = f" ({family_label})" if family_label else ""
            address = result.address
            if result.scope_id and "%" not in address:
                address = f"{address}%{result.scope_id}"
            address_suffix = f" on {address}{family}"

        print_safe(
            f"{GREEN}[+] OPEN: {result.port}/tcp{address_suffix}{RESET}"
        )

    def start_service_probe(self, open_port_count: int) -> None:
        """Render the service probe phase header."""
        self.stop()
        print_safe()
        print_safe(f"{BRIGHT_WHITE}[*] Native Service Probing{RESET}")
        print_safe(wrap_report(escape_controls(
            f"    Probing {open_port_count} open TCP endpoints on {self.target.target_host}"
        )))

    def complete_service_probe(self, elapsed_seconds: float) -> None:
        """Render the service probe phase completion line."""
        print_safe(
            f"{BRIGHT_WHITE}[*] Service Probe completed, "
            f"{elapsed_seconds:.2f}s elapsed{RESET}"
        )
        print_safe()
