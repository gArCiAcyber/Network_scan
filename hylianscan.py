#!/usr/bin/env python3
"""Main CLI orchestrator for hylianscan v0.6-dev."""

import argparse
from pathlib import Path

from core.banner import show_banner
from core.colors import (
    ALERT_RED,
    BRIGHT_WHITE,
    HACKER_GREEN,
    INFO_BLUE,
    MUTED_GRAY,
    RESET,
    WARNING_YELLOW,
    BOLD_GREEN, 
    BOLD_RED,    
    BOLD_BLUE,   
    BOLD_GOLD,   
    BOLD_WHITE,  
)
from core.panel import build_final_panel, format_open_port_line
from core.terminal import (
    build_exit_prompt,
    clear_dynamic_line,
    clear_screen,
    print_safe,
    write_dynamic_line,
)
from modules.subdomain import SubdomainFinding, SubdomainResult, enumerate_subdomains
from modules.target import TargetInfo, TargetResolutionError, format_target_orientation, resolve_target
from modules.tcp_scanner import PortScanResult, ScanResult, scan_tcp_ports


TOP_400_TCP_PORTS = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
    71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
    81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
    102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    113, 115, 117, 119, 123, 135, 137, 138, 139, 143,
    161, 162, 179, 194, 199, 389, 427, 443, 445, 465,
    512, 513, 514, 515, 520, 521, 523, 524, 548, 554,
    587, 631, 636, 646, 873, 902, 989, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1080, 1099, 1194, 1214, 1241,
    1311, 1433, 1434, 1521, 1604, 1720, 1723, 1755, 1812, 1813,
    1900, 1935, 2000, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    2121, 2222, 2375, 2376, 2483, 2484, 2601, 2604, 3000, 3128,
    3306, 3389, 3690, 4000, 4040, 4369, 4443, 4444, 4567, 5000,
    5001, 5060, 5061, 5432, 5601, 5672, 5800, 5900, 5901, 5984,
    5985, 5986, 6000, 6001, 6379, 6666, 6667, 7000, 7001, 7199,
    8000, 8008, 8009, 8080, 8081, 8088, 8090, 8161, 8443, 8888,
    9000, 9001, 9042, 9090, 9200, 9300, 9418, 9999, 10000, 11211,
    15672, 27017, 27018, 27019, 28017, 31337, 32768, 32769, 32770, 32771,
    32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 49152,
    49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 50000, 50030,
    50070, 61616, 62078, 49161, 49162, 49163, 49165, 49167, 49175, 49176,
    49400, 49999, 50002, 50006, 50300, 50389, 50500, 50636, 50800, 51103,
    51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555,
    55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900,
    62000, 63331, 64623, 64680, 65000, 65129, 65389, 65400, 65432, 65535,
    101, 112, 114, 116, 118, 120, 121, 122, 124, 125,
    126, 127, 128, 129, 130, 131, 132, 133, 134, 136,
    140, 141, 142, 144, 145, 146, 147, 148, 149, 150,
    151, 152, 153, 154, 155, 156, 157, 158, 159, 160,
    163, 164, 165, 166, 167, 168, 169, 170, 171, 172,
    173, 174, 175, 176, 177, 178, 180, 181, 182, 183,
    184, 185, 186, 187, 188, 189, 190, 191, 192, 193,
    195, 196, 197, 198, 200, 201, 202, 203, 204, 205,
    206, 207, 208, 209, 210, 211, 212, 213, 214, 215,
    216, 217, 218, 219, 220, 221, 222, 223, 224, 225,
    226, 227, 228, 229, 230, 231, 232, 233, 234, 235,
]


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
        "-w",
        "--wordlist",
        help="Path to a wordlist for subdomain brute-force enumeration.",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads for scanning. Default: 10.",
    )
    parser.add_argument(
        "-T",
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout per TCP port in seconds. Default: 1.0.",
    )
    parser.add_argument(
        "-o",
        "--output",
        nargs="?",
        const="hylianscan_results.txt",
        help="Save the final scan report inside the output directory.",
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


def validate_mode(args: argparse.Namespace) -> None:
    """Prevent ambiguous mode combinations."""
    if args.wordlist and (args.ports or args.top_ports):
        raise ValueError("Use --wordlist for subdomain mode or port flags for TCP mode, not both.")
    if args.wordlist and not args.output:
        raise ValueError("Saving to a text file (-o/--output) is mandatory for subdomain mode.")


def resolve_output_path(output_value: str | None) -> Path | None:
    """Resolve an output filename inside the local output directory."""
    if output_value is None:
        return None

    safe_filename = Path(output_value).name or "hylianscan_results.txt"
    project_root = Path(__file__).resolve().parent
    return project_root / "output" / safe_filename


def save_report(report_text: str, output_path: Path | None) -> None:
    """Persist the final report when requested by the operator."""
    if output_path is None:
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_text + "\n", encoding="utf-8")


def show_target_orientation(target: TargetInfo) -> None:
    """Render the target orientation block."""
    print()
    print(f"{INFO_BLUE}{format_target_orientation(target)}{RESET}")
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


def handle_subdomain_progress(completed: int, total: int, hostname: str) -> None:
    """Render thread-safe subdomain enumeration progress."""
    write_dynamic_line(
        f"{WARNING_YELLOW}[*] Enumerating subdomains... "
        f"{completed}/{total} tested (last: {hostname}){RESET}"
    )


def handle_subdomain_finding(finding: SubdomainFinding) -> None:
    """Render a resolved subdomain as soon as it is discovered."""
    clear_dynamic_line()
    print_safe(
        f"{HACKER_GREEN}[+] {finding.hostname:<45} -> {finding.ip_address}{RESET}"
    )


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


def run_subdomain_enumeration(
    base_domain: str,
    wordlist_path: str,
    threads: int,
) -> SubdomainResult:
    """Run threaded subdomain enumeration."""
    write_dynamic_line(f"{WARNING_YELLOW}[*] Enumerating subdomains...{RESET}")
    result = enumerate_subdomains(
        base_domain=base_domain,
        wordlist_path=wordlist_path,
        threads=threads,
        progress_callback=handle_subdomain_progress,
        finding_callback=handle_subdomain_finding,
    )
    clear_dynamic_line()
    return result


def build_subdomain_panel(result: SubdomainResult) -> str:
    """static report for subdomain enumeration results with Hylian colors."""
    nome_arquivo = f"output/{result.base_domain}_subdomains.txt"
    
    
    separator = f"{BOLD_GREEN}{'=' * 72}{RESET}"
    
   
    lines = [
        "",  
        separator,
        f"{BOLD_GREEN}[+] KOROK FOUND!{RESET}",
        f"{BOLD_BLUE}[+] {BOLD_WHITE}{len(result.findings)} {BOLD_BLUE}Unique subdomains found.{RESET}",
        f"{BOLD_RED}[+] Results in: {BOLD_GOLD}{nome_arquivo}{RESET}",
        separator,
        "" 
    ]
    return "\n".join(lines)


def main() -> None:
    """Coordinate the full CLI execution flow."""
    try:
        args = parse_arguments()
        validate_mode(args)
        timeout = validate_timeout(args.timeout)
        threads = validate_threads(args.threads)
        output_path = resolve_output_path(args.output)
        clear_screen()
        show_banner()

        if args.wordlist:
            subdomain_result = run_subdomain_enumeration(
                base_domain=args.target,
                wordlist_path=args.wordlist,
                threads=threads,
            )
            final_panel = build_subdomain_panel(subdomain_result)
        else:
            ports_to_scan = parse_ports_list(args)
            target = resolve_target(args.target)
            show_target_orientation(target)
            scan_result = run_port_scan(
                target=target,
                ports_to_scan=ports_to_scan,
                timeout=timeout,
                max_workers=threads,
            )
            final_panel = build_final_panel(scan_result)

        print(final_panel)
        save_report(final_panel, output_path)

        if output_path is not None:
            print_safe(f"[*] Report saved to: {output_path}")

    except ValueError as error:
        print(f"\n{ALERT_RED}[-] {error}{RESET}")
        
    except TargetResolutionError as error:
        print(f"\n{ALERT_RED}[-] {error}{RESET}")
        
    except KeyboardInterrupt:
        clear_dynamic_line()
        print(f"\n{ALERT_RED}[-] Scan aborted by the Ganondorf. Exiting safely.{RESET}")


if __name__ == "__main__":
    main()
