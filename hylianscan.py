#!/usr/bin/env python3
"""Main CLI orchestrator for hylianscan v0.8."""

import argparse
from pathlib import Path

from core.banner import show_banner
from core.colors import (
    ALERT_RED,
    BOLD_BLUE,
    HACKER_GREEN,
    INFO_BLUE,
    RESET,
    TRIFORCE_BLUE,
    TRIFORCE_GREEN,
    TRIFORCE_RED,
    WARNING_YELLOW,
)
from core.panel import build_final_panel, format_open_port_line
from core.passive_telemetry import PassiveActivityTelemetry
from core.terminal import (
    clear_dynamic_line,
    clear_screen,
    print_safe,
    write_dynamic_line,
)
from modules.json_exporter import write_subdomain_json_report, write_tcp_json_report
from modules.ports import TOP_400_TCP_PORTS
from modules.scan_stance import ScanStance, resolve_stance
from modules.subdomain import run_amass, run_subfinder
from modules.target import TargetInfo, TargetResolutionError, format_target_orientation, resolve_target
from modules.tcp_scanner import PortScanResult, ScanResult, scan_tcp_ports


DEFAULT_STANCE = "balanced"
STANCE_ALIAS_COLORS = {
    "Din": TRIFORCE_RED,
    "Nayru": TRIFORCE_BLUE,
    "Farore": TRIFORCE_GREEN,
}
PASSIVE_PROVIDER_LABELS = {
    "subfinder": ("Subfinder", TRIFORCE_BLUE),
    "amass": ("Amass", TRIFORCE_RED),
}


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for the scanner."""
    parser = argparse.ArgumentParser(
        prog="hylianscan",
        description="High-performance reconnaissance scanner for authorized targets.",
    )
    parser.add_argument("target", help="Target IP address or domain name.")
    parser.add_argument(
        "-p",
        "--ports",
        help=(
            "Ports to scan, using comma lists or ranges. "
            "Examples: 80,443 or 1-1000. Use '-p -' for 1-65535."
        ),
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        help="Scan the top N built-in TCP ports. Example: --top-ports 400.",
    )
    parser.add_argument(
        "-s",
        "--subfinder",
        action="store_true",
        help="Enable passive subdomain discovery using Subfinder.",
    )
    parser.add_argument(
        "-a",
        "--amass",
        action="store_true",
        help="Enable passive subdomain discovery using Amass.",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        help="Override the selected stance worker count.",
    )
    parser.add_argument(
        "-T",
        "--timeout",
        type=float,
        help="Override the selected stance timeout per TCP port in seconds.",
    )
    parser.add_argument(
        "--stance",
        default=DEFAULT_STANCE,
        help=(
            "TCP scan stance. Supports fast/din, balanced/nayru, "
            "and stealthier/farore. Default: balanced."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        nargs="?",
        const="hylianscan_results.txt",
        help=(
            "Save TCP reports inside output/ or choose a directory for "
            "passive subdomain results."
        ),
    )
    parser.add_argument(
        "--json-output",
        nargs="?",
        const="hylianscan_tcp_results.json",
        help="Save TCP or passive subdomain results as JSON inside the output directory.",
    )
    return parser.parse_args()


def validate_port(port: int) -> int:
    """Validate a TCP port number."""
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid TCP port: {port}")

    return port


def parse_port_range(port_range: str) -> list[int]:
    """Parse a hyphen-based port range."""
    start_text, end_text = port_range.split("-", maxsplit=1)
    start_port = validate_port(int(start_text.strip()))
    end_port = validate_port(int(end_text.strip()))

    if start_port > end_port:
        raise ValueError("Port range start cannot be greater than the end.")

    return list(range(start_port, end_port + 1))


def parse_custom_ports(ports_value: str) -> list[int]:
    """Parse comma-separated ports and ranges."""
    if ports_value.strip() == "-":
        return list(range(1, 65536))

    parsed_ports: list[int] = []

    for chunk in ports_value.split(","):
        item = chunk.strip()

        if not item:
            continue

        if "-" in item:
            parsed_ports.extend(parse_port_range(item))
        else:
            parsed_ports.append(validate_port(int(item)))

    return sorted(set(parsed_ports))


def parse_ports_list(args: argparse.Namespace) -> list[int]:
    """Return the selected TCP port list from CLI arguments."""
    if args.ports and args.top_ports:
        raise ValueError("Use either --ports or --top-ports, not both.")

    if args.ports:
        return parse_custom_ports(args.ports)

    if args.top_ports:
        if args.top_ports < 1:
            raise ValueError("--top-ports must be greater than zero.")

        if args.top_ports > len(TOP_400_TCP_PORTS):
            raise ValueError(f"--top-ports cannot exceed {len(TOP_400_TCP_PORTS)}.")

        return TOP_400_TCP_PORTS[: args.top_ports]

    return TOP_400_TCP_PORTS.copy()


def validate_timeout(timeout: float) -> float:
    """Validate the per-port connection timeout."""
    if timeout <= 0:
        raise ValueError("--timeout must be greater than zero.")

    return timeout


def validate_threads(threads: int) -> int:
    """Validate the requested worker thread count."""
    if threads <= 0:
        raise ValueError("--threads must be greater than zero.")

    return threads


def resolve_scan_stance(args: argparse.Namespace) -> ScanStance:
    """Resolve the selected scan stance and explicit CLI overrides."""
    explicit_threads = None
    explicit_timeout = None

    if args.threads is not None:
        explicit_threads = validate_threads(args.threads)

    if args.timeout is not None:
        explicit_timeout = validate_timeout(args.timeout)

    return resolve_stance(
        stance_value=args.stance,
        explicit_workers=explicit_threads,
        explicit_timeout=explicit_timeout,
    )


def get_passive_providers(args: argparse.Namespace) -> list[str]:
    """Return the selected passive discovery providers."""
    providers: list[str] = []

    if args.subfinder:
        providers.append("subfinder")

    if args.amass:
        providers.append("amass")

    return providers


def validate_mode(args: argparse.Namespace) -> None:
    """Prevent ambiguous mode combinations."""
    passive_providers = get_passive_providers(args)

    if passive_providers and (args.ports or args.top_ports):
        raise ValueError(
            "Use passive discovery provider flags or port flags for TCP mode, not both."
        )


def resolve_output_path(output_value: str | None) -> Path | None:
    """Resolve an output filename inside the local output directory."""
    if output_value is None:
        return None

    safe_filename = Path(output_value).name or "hylianscan_results.txt"
    project_root = Path(__file__).resolve().parent
    return project_root / "output" / safe_filename


def resolve_json_output_path(output_value: str | None) -> Path | None:
    """Resolve a JSON output filename inside the local output directory."""
    if output_value is None:
        return None

    safe_filename = Path(output_value).name or "hylianscan_tcp_results.json"

    if Path(safe_filename).suffix.lower() != ".json":
        safe_filename = f"{safe_filename}.json"

    project_root = Path(__file__).resolve().parent
    return project_root / "output" / safe_filename


def resolve_subdomain_json_output_path(output_value: str | None) -> Path | None:
    """Resolve a passive subdomain JSON output filename inside output/."""
    if output_value is None:
        return None

    safe_filename = Path(output_value).name or "hylianscan_subdomains.json"

    if safe_filename == "hylianscan_tcp_results.json":
        safe_filename = "hylianscan_subdomains.json"

    if Path(safe_filename).suffix.lower() != ".json":
        safe_filename = f"{safe_filename}.json"

    project_root = Path(__file__).resolve().parent
    return project_root / "output" / safe_filename


def resolve_subdomain_output_path(output_value: str | None) -> Path:
    """Resolve the mandatory passive subdomain output file path."""
    project_root = Path(__file__).resolve().parent
    default_output_dir = project_root / "output"

    if output_value is None:
        return default_output_dir / "hylianscan_subdomains.txt"

    if output_value == "hylianscan_results.txt":
        return default_output_dir / "subdomains.txt"

    requested_dir = Path(output_value).expanduser()

    if not requested_dir.is_absolute():
        requested_dir = project_root / requested_dir

    return requested_dir / "subdomains.txt"


def save_report(report_text: str, output_path: Path | None) -> None:
    """Persist the final report when requested by the operator."""
    if output_path is None:
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_text + "\n", encoding="utf-8")


def save_subdomain_results(subdomains: list[str], output_path: Path) -> None:
    """Persist passive subdomain results without flooding the terminal."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(subdomains) + "\n", encoding="utf-8")


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


def show_target_orientation(target: TargetInfo) -> None:
    """Render the target orientation block."""
    print()
    print(f"{INFO_BLUE}{format_target_orientation(target)}{RESET}")
    print()


def show_passive_providers(providers: list[str]) -> None:
    """Render selected passive discovery providers before enumeration starts."""
    print(f"{HACKER_GREEN}[*] Passive Discovery Providers:{RESET}")

    for provider in providers:
        label, color = PASSIVE_PROVIDER_LABELS[provider]
        print(f"{HACKER_GREEN}[+] {color}{label}{RESET}")

    print()


def show_scan_stance(stance: ScanStance) -> None:
    """Render the active TCP scan stance below target orientation."""
    alias_color = STANCE_ALIAS_COLORS.get(stance.lore_alias, INFO_BLUE)

    print(
        f"{BOLD_BLUE}[+] Active Stance: "
        f"{stance.name} ({alias_color}{stance.lore_alias}{BOLD_BLUE}){RESET}"
    )
    print(f"{BOLD_BLUE}[+] Workers: {stance.workers}{RESET}")
    print(f"{BOLD_BLUE}[+] Timeout: {stance.timeout:.2f}s{RESET}")
    print()


def handle_progress(completed: int, total: int, port: int) -> None:
    """Render thread-safe TCP progress updates from the scanner."""
    write_dynamic_line(
        f"{WARNING_YELLOW}[*] Scanning target ports... "
        f"{completed}/{total} completed (last: {port}){RESET}"
    )


def handle_open_port(result: PortScanResult) -> None:
    """Render an open port finding as soon as it is discovered."""
    clear_dynamic_line()
    print_safe(format_open_port_line(result))


def run_port_scan(
    target: TargetInfo,
    ports_to_scan: list[int],
    timeout: float,
    max_workers: int,
) -> ScanResult:
    """Run the threaded TCP scanner without embedding TCP logic in the CLI."""
    write_dynamic_line(f"{WARNING_YELLOW}[*] Scanning target ports...{RESET}")
    result = scan_tcp_ports(
        target_host=target.target_host,
        resolved_ip=target.resolved_ip,
        ports=ports_to_scan,
        timeout=timeout,
        max_workers=max_workers,
        progress_callback=handle_progress,
        open_port_callback=handle_open_port,
    )
    clear_dynamic_line()
    return result


def show_passive_activity(message: str | None) -> None:
    """Render one short passive discovery activity update."""
    if message is None:
        return

    write_dynamic_line(f"{HACKER_GREEN}[*] {message}{RESET}")


def build_passive_subdomain_summary(
    domain: str,
    subdomain_count: int,
    output_path: Path,
) -> str:
    """Build the final passive discovery summary."""
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
) -> str:
    """Run selected passive discovery providers and return a clean summary."""
    telemetry = PassiveActivityTelemetry()
    provider_results: dict[str, list[str]] = {}

    try:
        for provider in providers:
            telemetry_callback = lambda output, provider=provider: show_passive_activity(
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
    finally:
        clear_dynamic_line()

    show_passive_activity(telemetry.map_merge_activity())
    subdomains = merge_subdomain_results(provider_results)
    clear_dynamic_line()
    save_subdomain_results(subdomains, output_path)

    if json_output_path is not None:
        write_subdomain_json_report(
            target_domain=domain,
            provider_results=provider_results,
            output_path=json_output_path,
        )

    if not subdomains:
        print_safe(
            f"{ALERT_RED}[-] No passive subdomains were returned by selected providers.{RESET}"
        )

    return build_passive_subdomain_summary(domain, len(subdomains), output_path)


def main() -> None:
    """Coordinate the full CLI execution flow."""
    try:
        args = parse_arguments()
        validate_mode(args)
        clear_screen()
        show_banner()

        passive_providers = get_passive_providers(args)

        if passive_providers:
            output_path = resolve_subdomain_output_path(args.output)
            json_output_path = resolve_subdomain_json_output_path(args.json_output)
            show_passive_providers(passive_providers)
            final_panel = run_passive_subdomain_discovery(
                domain=args.target,
                providers=passive_providers,
                output_path=output_path,
                json_output_path=json_output_path,
            )
            print(final_panel)
        else:
            output_path = resolve_output_path(args.output)
            json_output_path = resolve_json_output_path(args.json_output)
            ports_to_scan = parse_ports_list(args)
            scan_stance = resolve_scan_stance(args)
            target = resolve_target(args.target)
            show_target_orientation(target)
            show_scan_stance(scan_stance)
            scan_result = run_port_scan(
                target=target,
                ports_to_scan=ports_to_scan,
                timeout=scan_stance.timeout,
                max_workers=scan_stance.workers,
            )
            final_panel = build_final_panel(scan_result)
            print(final_panel)
            save_report(final_panel, output_path)

            if json_output_path is not None:
                write_tcp_json_report(scan_result, json_output_path)

            if output_path is not None:
                print_safe(f"[*] Report saved to: {output_path}")

    except ValueError as error:
        print(f"\n{ALERT_RED}[-] {error}{RESET}")
        
    except TargetResolutionError as error:
        print(f"\n{ALERT_RED}[-] {error}{RESET}")
        
    except KeyboardInterrupt:
        clear_dynamic_line()
        print(f"\n{INFO_BLUE}[-] Scan aborted by {ALERT_RED}Ganondorf{INFO_BLUE}. Exiting safely.{RESET}")


if __name__ == "__main__":
    main()
