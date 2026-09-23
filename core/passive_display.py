"""Compact terminal output for passive discovery."""

import os
import threading
from pathlib import Path

from core.colors import HACKER_GREEN, LIGHT_BLUE, RESET, TRIFORCE_BLUE, TRIFORCE_RED
from core.nmap_live_display import NMAP_SPINNER_INTERVAL_SECONDS, select_spinner_frames
from core.terminal import clear_dynamic_line, print_safe, write_dynamic_line


PASSIVE_PROVIDER_LABELS = {
    "subfinder": ("Subfinder", TRIFORCE_BLUE),
    "amass": ("Amass", TRIFORCE_RED),
    "dnsx": ("DNSx", LIGHT_BLUE),
    "httpx": ("HTTPx", TRIFORCE_BLUE),
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
        label, color = PASSIVE_PROVIDER_LABELS[self._provider]
        if status == "completed":
            line = f"{HACKER_GREEN}[+]{RESET} {color}{label}{RESET} completed · {count} found"
        else:
            state = {
                "timed_out": "timeout",
                "interrupted": "cancelled",
                "failed": "failed",
                "skipped": "skipped",
            }.get(status, status)
            line = f"{HACKER_GREEN}[!]{RESET} {color}{label}{RESET} {state} · {count} found"
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
                label, color = PASSIVE_PROVIDER_LABELS[self._provider]
                line = f"{HACKER_GREEN}[>]{RESET} {color}{label}{RESET} {frame} {self._count} so far"
            write_dynamic_line(line)
            self._stop_event.wait(NMAP_SPINNER_INTERVAL_SECONDS)


def show_passive_providers(providers: list[str]) -> None:
    """Show enabled passive providers with their established colors."""
    for provider in providers:
        label, color = PASSIVE_PROVIDER_LABELS[provider]
        print_safe(f"{HACKER_GREEN}[+]{RESET} {color}{label}{RESET} enabled")


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
