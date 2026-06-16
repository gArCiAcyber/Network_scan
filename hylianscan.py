#!/usr/bin/env python3
"""Main CLI orchestrator for hylianscan v0.9."""

import threading
import time
from pathlib import Path

from core.banner import show_banner
from core.cli import (
    get_passive_providers,
    is_quiet_mode,
    parse_arguments,
    parse_ports_list,
    resolve_scan_scope_label,
    resolve_scan_stance,
    validate_max_rate,
    validate_mode,
)
from core.colors import (
    ALERT_RED,
    HACKER_GREEN,
    INFO_BLUE,
    RESET,
    TRIFORCE_BLUE,
    TRIFORCE_GREEN,
    TRIFORCE_RED,
)
from core.output import (
    resolve_json_output_path,
    resolve_output_path,
    resolve_subdomain_json_output_path,
    resolve_subdomain_output_path,
    save_report,
    save_subdomain_results,
)
from core.panel import build_final_panel, build_quiet_final_panel
from core.passive_telemetry import PassiveActivityTelemetry
from core.tcp_live_display import TCPScanDisplay
from core.terminal import (
    clear_dynamic_line,
    clear_screen,
    DynamicBlockRenderer,
    print_safe,
)
from modules.json_exporter import write_subdomain_json_report, write_tcp_json_report
from modules.scan_stance import ScanStance
from modules.subdomain import run_amass, run_subfinder
from modules.target import TargetInfo, TargetResolutionError, resolve_target
from modules.tcp_scanner import ScanResult, scan_tcp_ports


STANCE_ALIAS_COLORS = {
    "Din": TRIFORCE_RED,
    "Nayru": TRIFORCE_BLUE,
    "Farore": TRIFORCE_GREEN,
}
PASSIVE_PROVIDER_LABELS = {
    "subfinder": ("Subfinder", TRIFORCE_BLUE),
    "amass": ("Amass", TRIFORCE_RED),
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
            self._activities.append(f"{HACKER_GREEN}[*]{RESET} {message}")
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


def format_scan_stance_label(stance: ScanStance) -> str:
    """Return the display label for the active TCP scan stance."""
    alias_color = STANCE_ALIAS_COLORS.get(stance.lore_alias, INFO_BLUE)
    return f"{stance.name} ({alias_color}{stance.lore_alias}{RESET})"


def merge_subdomain_results(provider_results: dict[str, list[str]]) -> list[str]:
    """Merge provider results into one deduplicated and sorted subdomain list."""
    return sorted(
        {
            subdomain.strip().lower().strip(".")
            for subdomains in provider_results.values()
            for subdomain in subdomains
            if subdomain.strip()
        }
    )


def show_target_orientation(
    target: TargetInfo,
    stance: ScanStance,
    port_count: int,
) -> None:
    """Render the target orientation and active scan stance block."""
    alias_color = STANCE_ALIAS_COLORS.get(stance.lore_alias, INFO_BLUE)
    label_width = 14
    lines = ["[*] Target Orientation:"]

    lines.extend(
        [
            f"{'Host':<{label_width}}: {target.target_host}",
            f"{'Resolved IP':<{label_width}}: {target.resolved_ip}",
            (
                f"{'Stance':<{label_width}}: {stance.name} "
                f"({alias_color}{stance.lore_alias}{RESET}{INFO_BLUE})"
            ),
            f"{'Workers':<{label_width}}: {stance.workers}",
            f"{'Timeout':<{label_width}}: {stance.timeout:.2f}s",
            f"{'Scan Phase':<{label_width}}: Hylian TCP Connect Scan",
            f"{'Port Scope':<{label_width}}: {port_count} ports",
        ]
    )

    print()
    print(f"{INFO_BLUE}{chr(10).join(lines)}{RESET}")
    print()


def show_passive_providers(providers: list[str]) -> None:
    """Render selected passive discovery providers before enumeration starts."""
    print(f"{HACKER_GREEN}[*] Passive Discovery Providers:{RESET}")

    for provider in providers:
        label, color = PASSIVE_PROVIDER_LABELS[provider]
        print(f"{HACKER_GREEN}[+] {color}{label}{RESET}")

    print()


def run_port_scan(
    target: TargetInfo,
    ports_to_scan: list[int],
    timeout: float,
    max_workers: int,
    max_rate: float | None = None,
    quiet: bool = False,
) -> ScanResult:
    """Run the threaded TCP scanner without embedding TCP logic in the CLI."""
    display = None if quiet else TCPScanDisplay(target, len(ports_to_scan))

    if display is not None:
        display.start_connect_scan()

    result = scan_tcp_ports(
        target_host=target.target_host,
        resolved_ip=target.resolved_ip,
        ports=ports_to_scan,
        timeout=timeout,
        max_workers=max_workers,
        max_rate=max_rate,
        progress_callback=None if display is None else display.handle_progress,
        open_port_callback=None if display is None else display.handle_open_port,
        service_probe_start_callback=None if display is None else display.start_service_probe,
        service_probe_complete_callback=(
            None if display is None else display.complete_service_probe
        ),
    )

    if display is not None:
        clear_dynamic_line()

    return result


def build_passive_subdomain_summary(
    domain: str,
    subdomain_count: int,
    output_path: Path,
    quiet: bool = False,
) -> str:
    """Build the final passive discovery summary."""
    if quiet:
        return "\n".join(
            [
                f"Target: {domain}",
                f"Subdomains Found: {subdomain_count}",
                f"Output Path: {output_path}",
            ]
        )

    separator = f"{HACKER_GREEN}{'=' * 72}{RESET}"
    return "\n".join(
        [
            "",
            separator,
            f"{HACKER_GREEN}[+] SHEIKAH MAP UPDATED{RESET}",
            f"{HACKER_GREEN}[+] Target Realm       : {domain}{RESET}",
            f"{HACKER_GREEN}[+] Shrines Discovered : {subdomain_count}{RESET}",
            f"{HACKER_GREEN}[+] Slate Database     : {output_path}{RESET}",
            separator,
        ]
    )


def run_passive_subdomain_discovery(
    domain: str,
    providers: list[str],
    output_path: Path,
    json_output_path: Path | None = None,
    quiet: bool = False,
) -> str:
    """Run selected passive discovery providers and return a clean summary."""
    telemetry = None if quiet else PassiveActivityTelemetry()
    display = None if quiet else PassiveDiscoveryDisplay(domain)
    provider_results: dict[str, list[str]] = {}
    subdomains: list[str] = []

    if display is not None:
        display.start()

    try:
        for provider in providers:
            telemetry_callback = None

            if display is not None and telemetry is not None:
                telemetry_callback = lambda output, provider=provider: display.add_activity(
                    telemetry.map_provider_output(provider, output)
                )

            if provider == "subfinder":
                provider_results[provider] = run_subfinder(
                    domain,
                    telemetry_callback=telemetry_callback,
                )
            elif provider == "amass":
                provider_results[provider] = run_amass(
                    domain,
                    telemetry_callback=telemetry_callback,
                )

        if display is not None and telemetry is not None:
            display.add_activity(telemetry.map_merge_activity())

        subdomains = merge_subdomain_results(provider_results)
        save_subdomain_results(subdomains, output_path)

        if json_output_path is not None:
            write_subdomain_json_report(
                target_domain=domain,
                provider_results=provider_results,
                output_path=json_output_path,
            )
    finally:
        if display is not None:
            display.stop()

    if not subdomains and not quiet:
        print_safe(
            f"{ALERT_RED}[-] No passive subdomains were returned by selected providers.{RESET}"
        )

    return build_passive_subdomain_summary(domain, len(subdomains), output_path, quiet)


def main() -> None:
    """Coordinate the full CLI execution flow."""
    quiet = False

    try:
        args = parse_arguments()
        validate_mode(args)
        quiet = is_quiet_mode(args)

        if not quiet:
            clear_screen()
            show_banner()

        passive_providers = get_passive_providers(args)

        if passive_providers:
            output_path = resolve_subdomain_output_path(args.output)
            json_output_path = resolve_subdomain_json_output_path(args.json_output)

            if not quiet:
                show_passive_providers(passive_providers)

            final_panel = run_passive_subdomain_discovery(
                domain=args.target,
                providers=passive_providers,
                output_path=output_path,
                json_output_path=json_output_path,
                quiet=quiet,
            )
            print(final_panel)
        else:
            output_path = resolve_output_path(args.output)
            json_output_path = resolve_json_output_path(args.json_output)
            ports_to_scan = parse_ports_list(args)
            scan_stance = resolve_scan_stance(args)
            max_rate = validate_max_rate(args.max_rate)
            scan_scope = resolve_scan_scope_label(args)
            target = resolve_target(args.target)

            if not quiet:
                show_target_orientation(target, scan_stance, len(ports_to_scan))

            scan_result = run_port_scan(
                target=target,
                ports_to_scan=ports_to_scan,
                timeout=scan_stance.timeout,
                max_workers=scan_stance.workers,
                max_rate=max_rate,
                quiet=quiet,
            )
            if quiet:
                final_panel = build_quiet_final_panel(
                    scan_result,
                    scan_scope=scan_scope,
                )
            else:
                final_panel = build_final_panel(
                    scan_result,
                    scan_scope=scan_scope,
                    scan_stance=format_scan_stance_label(scan_stance),
                )

            print(final_panel)
            save_report(final_panel, output_path)

            if json_output_path is not None:
                write_tcp_json_report(scan_result, json_output_path)

            if output_path is not None and not quiet:
                print_safe(f"[*] Report saved to: {output_path}")

    except ValueError as error:
        if quiet:
            print(f"Error: {error}")
        else:
            print(f"\n{ALERT_RED}[-] {error}{RESET}")
        
    except TargetResolutionError as error:
        if quiet:
            print(f"Error: {error}")
        else:
            print(f"\n{ALERT_RED}[-] {error}{RESET}")
        
    except KeyboardInterrupt:
        if quiet:
            print("Scan aborted. Exiting safely.")
        else:
            clear_dynamic_line()
            print(f"\n{INFO_BLUE}[-] Scan aborted by {ALERT_RED}Ganondorf{INFO_BLUE}. Exiting safely.{RESET}")


if __name__ == "__main__":
    main()
