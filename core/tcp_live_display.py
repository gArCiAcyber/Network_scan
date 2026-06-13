"""Live TCP scan rendering helpers for hylianscan."""

import sys
import time

from core.colors import HACKER_GREEN, RESET
from core.terminal import clear_dynamic_line, print_safe, write_dynamic_line
from modules.target import TargetInfo
from modules.tcp_scanner import PortScanResult


PROGRESS_BAR_WIDTH = 24
PROGRESS_FILLED_BLOCK = "\u2588"
PROGRESS_EMPTY_BLOCK = "\u2591"
PROGRESS_FILLED_FALLBACK = "#"
PROGRESS_EMPTY_FALLBACK = "-"
PROGRESS_EMPTY_COLOR = "\033[90m"
PROGRESS_RGB_START = (46, 204, 113)
PROGRESS_RGB_END = (52, 152, 219)


def format_duration(seconds: float) -> str:
    """Return a compact H:MM:SS duration."""
    normalized_seconds = max(0, int(round(seconds)))
    hours, remainder = divmod(normalized_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}"


def clamp_progress(progress: float) -> float:
    """Clamp progress into the terminal progress-bar range."""
    return max(0.0, min(1.0, progress))


def supports_progress_blocks() -> bool:
    """Return True when the terminal encoding can render block symbols."""
    encoding = sys.stdout.encoding or "utf-8"

    try:
        f"{PROGRESS_FILLED_BLOCK}{PROGRESS_EMPTY_BLOCK}".encode(encoding)
    except UnicodeEncodeError:
        return False

    return True


def interpolate_rgb(
    start_rgb: tuple[int, int, int],
    end_rgb: tuple[int, int, int],
    ratio: float,
) -> tuple[int, int, int]:
    """Interpolate one RGB color stop."""
    safe_ratio = clamp_progress(ratio)
    return tuple(
        round(start + (end - start) * safe_ratio)
        for start, end in zip(start_rgb, end_rgb, strict=True)
    )


def colorize_truecolor(text: str, rgb: tuple[int, int, int]) -> str:
    """Apply ANSI truecolor to one text fragment."""
    red, green, blue = rgb
    return f"\033[38;2;{red};{green};{blue}m{text}{RESET}"


def render_rgb_progress_bar(progress: float, width: int = PROGRESS_BAR_WIDTH) -> str:
    """Render an ANSI truecolor TCP progress bar."""
    safe_progress = clamp_progress(progress)
    safe_width = max(1, width)
    filled_count = round(safe_progress * safe_width)
    filled_symbol = PROGRESS_FILLED_BLOCK
    empty_symbol = PROGRESS_EMPTY_BLOCK

    if not supports_progress_blocks():
        filled_symbol = PROGRESS_FILLED_FALLBACK
        empty_symbol = PROGRESS_EMPTY_FALLBACK

    parts: list[str] = []

    for index in range(filled_count):
        ratio = index / max(1, safe_width - 1)
        rgb = interpolate_rgb(PROGRESS_RGB_START, PROGRESS_RGB_END, ratio)
        parts.append(colorize_truecolor(filled_symbol, rgb))

    empty_count = safe_width - filled_count

    if empty_count:
        parts.append(f"{PROGRESS_EMPTY_COLOR}{empty_symbol * empty_count}{RESET}")

    return "".join(parts)


class TCPScanDisplay:
    """Render phase-oriented TCP scan activity."""

    def __init__(self, target: TargetInfo, port_count: int) -> None:
        self.target = target
        self.port_count = port_count
        self.connect_started_at = time.time()

    def start_connect_scan(self) -> None:
        """Start connect scan timing without adding extra header noise."""
        self.connect_started_at = time.time()

    def handle_progress(self, completed: int, total: int, _port: int) -> None:
        """Render dynamic TCP connect scan timing."""
        if completed <= 0 or total <= 0:
            return

        elapsed_seconds = max(0.0, time.time() - self.connect_started_at)
        progress = completed / total
        percent_done = progress * 100
        estimated_total = elapsed_seconds / completed * total
        remaining_seconds = max(0.0, estimated_total - elapsed_seconds)
        progress_bar = render_rgb_progress_bar(progress)

        write_dynamic_line(
            f"{HACKER_GREEN}[*]{RESET} TCP Scan: About "
            f"[{progress_bar}] {percent_done:.1f}% | "
            f"{completed}/{total} ports | ETA {format_duration(remaining_seconds)}"
        )

    def handle_open_port(self, result: PortScanResult) -> None:
        """Render a permanent open-port discovery line."""
        clear_dynamic_line()
        print_safe(f"{HACKER_GREEN}[+] OPEN: {result.port}/tcp{RESET}")

    def start_service_probe(self, open_port_count: int) -> None:
        """Render the service probe phase header."""
        clear_dynamic_line()
        print_safe()
        print_safe(f"{HACKER_GREEN}[*] Hylian Service Probe{RESET}")
        print_safe(
            f"{HACKER_GREEN}[*] Probing {open_port_count} discovered services "
            f"on {self.target.target_host}{RESET}"
        )

    def complete_service_probe(self, elapsed_seconds: float) -> None:
        """Render the service probe phase completion line."""
        print_safe(
            f"{HACKER_GREEN}[*] Service Probe completed, "
            f"{elapsed_seconds:.2f}s elapsed{RESET}"
        )
        print_safe()
