"""Command-line parsing and argument normalization."""

import argparse

from modules.ports import TOP_400_TCP_PORTS
from modules.scan_stance import ScanStance, resolve_stance


DEFAULT_STANCE = "balanced"


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
        "--subfinder-path",
        help="Path to the Subfinder executable when it is not available in PATH.",
    )
    parser.add_argument(
        "-a",
        "--amass",
        action="store_true",
        help="Enable passive subdomain discovery using Amass.",
    )
    parser.add_argument(
        "--amass-path",
        help="Path to the Amass executable when it is not available in PATH.",
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
        "--max-rate",
        type=float,
        help="Limit how many new TCP connection attempts are started per second.",
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
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce terminal output for scripting and automation.",
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

    if args.top_ports is not None:
        if args.top_ports < 1:
            raise ValueError("--top-ports must be greater than zero.")

        if args.top_ports > len(TOP_400_TCP_PORTS):
            raise ValueError(f"--top-ports cannot exceed {len(TOP_400_TCP_PORTS)}.")

        return TOP_400_TCP_PORTS[: args.top_ports]

    return TOP_400_TCP_PORTS.copy()


def resolve_scan_scope_label(args: argparse.Namespace) -> str:
    """Return the final panel scan scope label for the selected port mode."""
    if args.ports:
        return "Custom Port List"

    if args.top_ports:
        return "Selected Port List"

    return "Default Target List"


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


def validate_max_rate(max_rate: float | None) -> float | None:
    """Validate the optional TCP connection start rate limit."""
    if max_rate is None:
        return None

    if max_rate <= 0:
        raise ValueError("--max-rate must be greater than zero.")

    return max_rate


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


def is_quiet_mode(args: argparse.Namespace) -> bool:
    """Return True when automation-friendly quiet output is enabled."""
    return bool(getattr(args, "quiet", False))
