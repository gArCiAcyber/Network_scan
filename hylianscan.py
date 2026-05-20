#!/usr/bin/env python3
"""Main CLI orchestrator for hylianscan v0.4."""

from core.banner import show_banner
from core.colors import ALERT_RED, INFO_BLUE, RESET, WARNING_YELLOW
from core.panel import build_final_panel, format_open_port_line
from core.terminal import (
    build_exit_prompt,
    clear_dynamic_line,
    clear_screen,
    print_safe,
    wait_for_enter_safely,
    write_dynamic_line,
)
from modules.target import TargetInfo, TargetResolutionError, format_target_orientation, resolve_target
from modules.tcp_scanner import PortScanResult, ScanResult, scan_tcp_ports


def read_target() -> str:
    """Read the target host or IP from the operator."""
    return input("Ready to investigate. Master, what is the target? ").strip()


def show_target_orientation(target: TargetInfo) -> None:
    """Render the target orientation block."""
    print()
    print(f"{INFO_BLUE}{format_target_orientation(target)}{RESET}")
    print()


def handle_progress(completed: int, total: int, port: int) -> None:
    """Render thread-safe progress updates from the scanner."""
    write_dynamic_line(
        f"{WARNING_YELLOW}[*] Scanning target ports... "
        f"{completed}/{total} completed (last: {port}){RESET}"
    )


def handle_open_port(result: PortScanResult) -> None:
    """Render an open port finding as soon as it is discovered."""
    clear_dynamic_line()
    print_safe(format_open_port_line(result))


def run_investigation(target: TargetInfo) -> ScanResult:
    """Run the threaded scanner without embedding TCP logic in the CLI."""
    write_dynamic_line(f"{WARNING_YELLOW}[*] Scanning target ports...{RESET}")
    result = scan_tcp_ports(
        target_host=target.target_host,
        resolved_ip=target.resolved_ip,
        progress_callback=handle_progress,
        open_port_callback=handle_open_port,
    )
    clear_dynamic_line()
    return result


def main() -> None:
    """Coordinate the full CLI execution flow."""
    try:
        clear_screen()
        show_banner()
        target_input = read_target()
        target = resolve_target(target_input)
        show_target_orientation(target)
        scan_result = run_investigation(target)
        print(build_final_panel(scan_result))
        wait_for_enter_safely(build_exit_prompt())
    except TargetResolutionError as error:
        print(f"\n{ALERT_RED}[-] {error}{RESET}")
        wait_for_enter_safely(build_exit_prompt())
    except KeyboardInterrupt:
        clear_dynamic_line()
        print(f"\n{ALERT_RED}[-] Scan aborted by the Master. Exiting safely.{RESET}")


if __name__ == "__main__":
    main()

