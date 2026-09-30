"""Passive discovery terminal rendering helpers."""

import os
import threading
import time
from pathlib import Path
from collections.abc import Mapping

from core.colors import (
    ALERT_RED,
    GREEN,
    RESET,
    TRIFORCE_BLUE,
    TRIFORCE_RED,
)
from core.terminal import DynamicBlockRenderer, escape_controls, wrap_report
from modules.subdomain import ProviderRunResult


PASSIVE_PROVIDER_LABELS = {
    "subfinder": ("Subfinder", TRIFORCE_BLUE),
    "amass": ("Amass", TRIFORCE_RED),
    "dnsx": ("DNSx", TRIFORCE_BLUE),
}
PASSIVE_SPINNER_FRAMES = ("|", "/", "-", "\\")
PASSIVE_SPINNER_INTERVAL_SECONDS = 0.12
PASSIVE_MAX_ACTIVITY_LINES = 8


class PassiveDiscoveryDisplay:
    """Render passive discovery spinner and deduplicated activity messages."""

    def __init__(self, domain: str) -> None:
        self.domain = domain
        self._renderer = DynamicBlockRenderer()
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._frame_index = 0
        self._activities: list[str] = []
        self._seen_activities: set[str] = set()

    def start(self) -> None:
        """Start the passive discovery spinner."""
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def add_activity(self, message: str | None) -> None:
        """Add one deduplicated activity message under the spinner."""
        if message is None or message in self._seen_activities:
            return

        with self._lock:
            self._seen_activities.add(message)
            self._activities.append(format_passive_activity_line(message))
            self._activities = self._activities[-PASSIVE_MAX_ACTIVITY_LINES:]
            self._render_locked()

    def stop(self) -> None:
        """Stop the spinner and leave the last activity messages visible."""
        self._stop_event.set()

        if self._thread is not None:
            self._thread.join()

        with self._lock:
            if self._activities:
                self._renderer.render(self._activities)
                self._renderer.release()
            else:
                self._renderer.clear()

    def _spin(self) -> None:
        """Update the spinner line until passive discovery finishes."""
        while not self._stop_event.is_set():
            with self._lock:
                self._render_locked()

            time.sleep(PASSIVE_SPINNER_INTERVAL_SECONDS)

    def _render_locked(self) -> None:
        """Render the current passive discovery block."""
        frame = PASSIVE_SPINNER_FRAMES[self._frame_index % len(PASSIVE_SPINNER_FRAMES)]
        self._frame_index += 1
        spinner_line = (
            f"{ALERT_RED}[*]{RESET} "
            f"Enumerating subdomains for {self.domain}... "
            f"{ALERT_RED}{frame}{RESET}"
        )
        self._renderer.render([spinner_line, *self._activities])


def format_passive_activity_line(message: str) -> str:
    """Return one formatted passive activity line."""
    for marker in ("[*]", "[+]"):
        if message.startswith(marker):
            return f"{GREEN}{marker}{RESET} {message[len(marker):].strip()}"

    return f"{GREEN}[*]{RESET} {message}"


def format_relative_output_path(output_path: Path) -> str:
    """Return a display-safe path relative to the current working directory."""
    try:
        display_path = str(output_path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        display_path = output_path.name
    except Exception:
        display_path = str(output_path)

    return display_path.replace(os.sep, "/")


def show_passive_providers(providers: list[str]) -> None:
    """Render selected passive discovery providers before enumeration starts."""
    print(f"{GREEN}[*] Passive Discovery Providers:{RESET}")

    for provider in providers:
        label, color = PASSIVE_PROVIDER_LABELS[provider]
        print(f"{GREEN}[+] {color}{label}{RESET} enabled")

    print()


def format_passive_provider_count_message(provider: str, candidate_count: int) -> str:
    """Return one provider result-count activity message."""
    label = PASSIVE_PROVIDER_LABELS[provider][0]
    return f"[+] {label} returned {candidate_count} candidates"


def build_passive_subdomain_summary(
    domain: str,
    raw_discovery_count: int,
    unique_subdomain_count: int,
    output_path: Path,
    quiet: bool = False,
    provider_results: Mapping[str, ProviderRunResult] | None = None,
) -> str:
    """Build the final passive discovery summary."""
    display_output_path = format_relative_output_path(output_path)

    lines = [
        f"Hylianscan passive discovery report for {domain}",
        f"Provider candidates: {raw_discovery_count} (before cross-provider deduplication)",
        f"Unique names saved: {unique_subdomain_count}",
    ]
    if provider_results:
        lines.extend(["", f"{'PROVIDER':<12} {'STATUS':<12} NAMES"])
        for provider, result in provider_results.items():
            lines.append(f"{provider:<12} {result.status:<12} {len(result.subdomains)}")
        dnsx = provider_results.get("dnsx")
        lines.append(
            "DNS validation: DNSx A/AAAA results; service reachability untested."
            if dnsx and dnsx.status == "completed" else
            "DNS validation: incomplete; service reachability untested."
            if dnsx else "DNS validation: not requested; names are passive candidates."
        )
    lines.append(f"Output Path: {display_output_path}")
    report = wrap_report(escape_controls("\n".join(lines), multiline=True))
    if quiet:
        return report
    return f"\n{GREEN}SHEIKAH MAP\n{report}{RESET}"
