"""Compact terminal output for passive discovery."""

import os
import threading
from pathlib import Path

from core.colors import HACKER_GREEN, RESET
from core.nmap_live_display import NMAP_SPINNER_INTERVAL_SECONDS, select_spinner_frames
from core.terminal import clear_dynamic_line, print_safe, write_dynamic_line


PASSIVE_PROVIDER_LABELS = {
    "subfinder": "Subfinder",
    "amass": "Amass",
    "dnsx": "DNSx",
    "httpx": "HTTPx",
}


class PassiveDiscoveryDisplay:
    """Render one updating status line for the current passive stage."""

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._frames = select_spinner_frames()
        self._frame_index = 0
        self._provider = ""
        self._count = 0
        self._lock = threading.Lock()

    def start_provider(self, provider: str) -> None:
        self.stop()
        with self._lock:
            self._provider = provider
            self._count = 0
            self._frame_index = 0
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()

    def update_count(self, count: int) -> None:
        with self._lock:
            self._count = count

    def finish_provider(self, status: str, count: int) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=NMAP_SPINNER_INTERVAL_SECONDS * 2)
            self._thread = None
        label = PASSIVE_PROVIDER_LABELS[self._provider]
        if status == "completed":
            line = f"[+] {label} concluído · {count} encontrados"
        else:
            state = {
                "timed_out": "timeout",
                "interrupted": "cancelado",
                "failed": "falhou",
                "skipped": "ignorado",
            }.get(status, status)
            line = f"[!] {label} {state} · {count} encontrados"
        print_safe(line)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=NMAP_SPINNER_INTERVAL_SECONDS * 2)
            self._thread = None
        clear_dynamic_line()

    def _spin(self) -> None:
        while not self._stop_event.is_set():
            with self._lock:
                frame = self._frames[self._frame_index % len(self._frames)]
                self._frame_index += 1
                line = f"[>] {PASSIVE_PROVIDER_LABELS[self._provider]} {frame} {self._count} até agora"
            write_dynamic_line(line)
            self._stop_event.wait(NMAP_SPINNER_INTERVAL_SECONDS)


def format_relative_output_path(output_path: Path) -> str:
    """Return a display-safe path relative to the current working directory."""
    try:
        display_path = str(output_path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        display_path = output_path.name
    except Exception:
        display_path = str(output_path)

    return display_path.replace(os.sep, "/")


def build_passive_subdomain_summary(
    domain: str,
    raw_discovery_count: int,
    unique_subdomain_count: int,
    output_path: Path,
    quiet: bool = False,
) -> str:
    """Build the final passive discovery summary."""
    display_output_path = format_relative_output_path(output_path)
    if quiet:
        return "\n".join(
            [
                f"Target: {domain}",
                f"Raw Discoveries: {raw_discovery_count}",
                f"Unique Subdomains: {unique_subdomain_count}",
                f"Output Path: {display_output_path}",
            ]
        )

    separator = f"{HACKER_GREEN}{'=' * 72}{RESET}"
    return "\n".join(
        [
            "",
            separator,
            f"{HACKER_GREEN}[+] SHEIKAH MAP UPDATED{RESET}",
            f"{HACKER_GREEN}[+] Target Realm       : {domain}{RESET}",
            f"{HACKER_GREEN}[+] Raw Discoveries    : {raw_discovery_count}{RESET}",
            f"{HACKER_GREEN}[+] Unique Subdomains  : {unique_subdomain_count}{RESET}",
            f"{HACKER_GREEN}[+] Slate Database     : {display_output_path}{RESET}",
            separator,
        ]
    )
