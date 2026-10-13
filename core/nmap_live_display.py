"""Live terminal feedback for optional Nmap Service Scan."""

import threading
import sys
import shutil
from collections.abc import Sequence

from core.colors import BRIGHT_WHITE, RESET
from core.terminal import clear_dynamic_line, escape_controls, print_safe, wrap_report, write_dynamic_line
from modules.nmap_enrichment import format_enriched_ports


NMAP_BRAILLE_SPINNER_FRAMES = (
    "\u280b",
    "\u2819",
    "\u2839",
    "\u2838",
    "\u283c",
    "\u2834",
    "\u2826",
    "\u2827",
    "\u2807",
    "\u280f",
)
NMAP_ASCII_SPINNER_FRAMES = ("|", "/", "-", "\\")
NMAP_SPINNER_INTERVAL_SECONDS = 0.12


class NmapServiceScanDisplay:
    """Render lightweight progress while Nmap service detection runs."""

    def __init__(self, target: str, ports: Sequence[int]) -> None:
        self.target = target
        self.ports = tuple(sorted(set(ports)))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._frame_index = 0
        self._spinner_frames = select_spinner_frames()

    def start(self) -> None:
        """Show the concrete Nmap scope before starting its spinner."""
        print_safe()
        print_safe(f"{BRIGHT_WHITE}[*] Nmap Service/Version Detection{RESET}")
        print_safe(wrap_report(escape_controls(
            f"Target          : {self.target}\n"
            f"Ports scanned   : {format_enriched_ports(self.ports)}\n"
            "Status          : running",
            multiline=True,
        )))
        self._write_spinner_frame()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the spinner and clear the dynamic line."""
        self._stop_event.set()

        if self._thread is not None:
            self._thread.join()

        clear_dynamic_line()

    def _spin(self) -> None:
        """Update the spinner line until Nmap finishes."""
        while not self._stop_event.wait(NMAP_SPINNER_INTERVAL_SECONDS):
            self._write_spinner_frame()

    def _write_spinner_frame(self) -> None:
        """Write one dynamic spinner frame."""
        frame = self._spinner_frames[self._frame_index % len(self._spinner_frames)]
        self._frame_index += 1
        width = max(1, shutil.get_terminal_size(fallback=(100, 24)).columns - 1)
        message = "Running Nmap service/version detection..."
        if len(message) + 2 > width:
            message = "Nmap service detection..."
        write_dynamic_line(f"{BRIGHT_WHITE}{frame}{RESET} " + message[:max(0, width - 2)])


def select_spinner_frames(encoding: str | None = None) -> tuple[str, ...]:
    """Return Braille spinner frames when the active output encoding supports them."""
    output_encoding = encoding or sys.stdout.encoding or ""

    try:
        "".join(NMAP_BRAILLE_SPINNER_FRAMES).encode(output_encoding)
    except (LookupError, UnicodeEncodeError):
        return NMAP_ASCII_SPINNER_FRAMES

    return NMAP_BRAILLE_SPINNER_FRAMES
