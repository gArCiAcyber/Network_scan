"""Command-line parsing and argument normalization."""

import argparse

from core.version import APP_NAME, APP_VERSION
from modules.ports import TOP_400_TCP_PORTS
from modules.port_profiles import format_port_profile_label, resolve_port_profile
from modules.scan_profiles import ScanProfile, resolve_scan_profile
from modules.scan_stance import ScanStance, resolve_stance


DEFAULT_STANCE = "balanced"


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments for the scanner."""
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description=(
            "High-performance reconnaissance scanner for authorized targets.\n\n"
            "Examples:\n"
            "  hylianscan example.com -t 50 --max-rate 10\n\n"
            "  hylianscan example.com\n"
            "  hylianscan example.com --profile web\n"
            "  hylianscan example.com --subfinder --amass"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    general_group = parser.add_argument_group("General")
    target_group = parser.add_argument_group("Target")
    scan_scope_group = parser.add_argument_group("Scan Scope")
    scan_behavior_group = parser.add_argument_group("Scan Behavior")
    passive_group = parser.add_argument_group("Passive Discovery")
    performance_group = parser.add_argument_group("Performance")
    integrations_group = parser.add_argument_group("Integrations")
    output_group = parser.add_argument_group("Output")
    import_group = parser.add_argument_group("Import")
    information_group = parser.add_argument_group("Information")

    general_group.add_argument(
        "-h",
        "--help",
        action="help",
        help="show this help message and exit.",
    )
    general_group.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {APP_VERSION}",
    )
    information_group.add_argument(
        "--list-scan-profiles",
        "--list-profiles",
        dest="list_scan_profiles",
        action="store_true",
        help="List complete built-in scan profiles and exit without scanning.",
    )
    information_group.add_argument(
        "--list-port-profiles",
        action="store_true",
        help="List built-in TCP port profiles and exit without scanning.",
    )
    information_group.add_argument(
        "--list-stances",
        action="store_true",
        help="List built-in TCP scan stances and exit without scanning.",
    )
    import_group.add_argument(
        "--nmap-xml",
        metavar="PATH",
        help="Import an existing Nmap XML file and exit without scanning.",
    )
    integrations_group.add_argument(
        "--nmap",
        action="store_true",
        help="Run optional Nmap service/version enrichment after native TCP scanning.",
    )
    integrations_group.add_argument(
        "--nmap-path",
        metavar="PATH",
        help="Path to the Nmap executable for optional live enrichment.",
    )
    address_family_group = scan_behavior_group.add_mutually_exclusive_group()
    address_family_group.add_argument(
        "--ipv4",
        dest="address_family",
        action="store_const",
        const="ipv4",
        help="Resolve and scan IPv4 addresses only.",
    )
    address_family_group.add_argument(
        "--ipv6",
        dest="address_family",
        action="store_const",
        const="ipv6",
        help="Resolve and scan IPv6 addresses only.",
    )
    address_family_group.add_argument(
        "--dual-stack",
        dest="address_family",
        action="store_const",
        const="dual-stack",
        help="Resolve and scan both IPv4 and IPv6 addresses (default).",
    )
    discovery_group = scan_behavior_group.add_mutually_exclusive_group()
    discovery_group.add_argument(
        "--host-discovery",
        choices=("tcp", "icmp"),
        help="Run optional TCP or ICMP host discovery before port scanning.",
    )
    discovery_group.add_argument(
        "--tcp-discovery",
        dest="host_discovery",
        action="store_const",
        const="tcp",
        help="Alias for --host-discovery tcp.",
    )
    discovery_group.add_argument(
        "--icmp-discovery",
        dest="host_discovery",
        action="store_const",
        const="icmp",
        help="Alias for --host-discovery icmp.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        metavar="TARGET",
        help="Target host string: IP address, hostname, or domain name.",
    )
    target_group.add_argument(
        "-u",
        "--url",
        dest="target_url",
        metavar="TARGET",
        help=(
            "Alternate explicit target host flag; accepts an IP address, "
            "hostname, or domain name."
        ),
    )
    scan_scope_group.add_argument(
        "-p",
        "--ports",
        metavar="PORTS",
        help=(
            "Ports to scan, using comma lists or ranges. "
            "Examples: 80,443 or 1-1000. Use '-p -' for 1-65535."
        ),
    )
    scan_scope_group.add_argument(
        "--top-ports",
        type=int,
        metavar="N",
        help="Scan the top N built-in TCP ports. Example: --top-ports 400.",
    )
    scan_scope_group.add_argument(
        "--profile",
        "--scan-profile",
        dest="scan_profile",
        metavar="NAME",
        help="Apply a complete scan profile: quick, web, or cautious.",
    )
    scan_scope_group.add_argument(
        "--port-profile",
        metavar="NAME",
        help=(
            "Use a predefined TCP port profile. Supports quick/kokiri, "
            "web/sheikah, mail/rito, admin/castle, and bugbounty/triforce."
        ),
    )
    passive_group.add_argument(
        "-s",
        "--subfinder",
        action="store_true",
        help="Enable passive subdomain discovery using Subfinder.",
    )
    integrations_group.add_argument(
        "--subfinder-path",
        metavar="PATH",
        help="Path to the Subfinder executable when it is not available in PATH.",
    )
    passive_group.add_argument(
        "-a",
        "--amass",
        action="store_true",
        help="Enable passive subdomain discovery using Amass.",
    )
    integrations_group.add_argument(
        "--amass-path",
        metavar="PATH",
        help="Path to the Amass executable when it is not available in PATH.",
    )
    passive_group.add_argument(
        "--httpx",
        action="store_true",
        help="Probe passive-discovery results with ProjectDiscovery HTTPx.",
    )
    integrations_group.add_argument(
        "--httpx-path",
        metavar="PATH",
        help="Path to the HTTPx executable when it is not available in PATH.",
    )
    performance_group.add_argument(
        "-t",
        "--threads",
        type=int,
        metavar="N",
        help="Override the selected stance worker count.",
    )
    performance_group.add_argument(
        "-T",
        "--timeout",
        type=float,
        metavar="SEC",
        help="Override the selected stance timeout per TCP port in seconds.",
    )
    performance_group.add_argument(
        "--max-rate",
        type=float,
        metavar="RATE",
        help="Limit how many new TCP connection attempts are started per second.",
    )
    http_probing_group = scan_behavior_group.add_mutually_exclusive_group()
    http_probing_group.add_argument(
        "--http-probing",
        dest="http_probing",
        action="store_true",
        help="Probe discovered HTTP/HTTPS services (overrides the profile default).",
    )
    http_probing_group.add_argument(
        "--no-http-probing",
        dest="http_probing",
        action="store_false",
        help="Skip HTTP/HTTPS probes after TCP discovery.",
    )
    scan_behavior_group.add_argument(
        "-mc",
        "--match-code",
        metavar="CODES",
        help=(
            "Report only HTTP/HTTPS findings with matching status codes. "
            "Supports comma lists and ranges, such as 200,301-304."
        ),
    )
    scan_behavior_group.add_argument(
        "--stance",
        metavar="NAME",
        help=(
            "TCP scan stance. Supports fast/din, balanced/nayru, "
            "and stealthier/farore. Default: balanced."
        ),
    )
    output_group.add_argument(
        "-o",
        "--output",
        nargs="?",
        const="hylianscan_results.txt",
        metavar="PATH",
        help="Save TXT reports for TCP scans, passive discovery, or Nmap XML import.",
    )
    output_group.add_argument(
        "--json-output",
        nargs="?",
        const="hylianscan_tcp_results.json",
        metavar="PATH",
        help="Save TCP, passive subdomain, or Nmap XML import results as JSON.",
    )
    output_group.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce terminal output for scripting and automation.",
    )
    parser.set_defaults(
        address_family="dual-stack",
        host_discovery=None,
        http_probing=None,
    )
    args = parser.parse_args()

    try:
        if is_information_command(args) or is_nmap_xml_import_command(args):
            if args.target and args.target_url:
                raise ValueError(
                    "Provide the target either positionally or with -u/--url, not both."
                )
            args.target = args.target_url or args.target
        else:
            args.target = resolve_target_argument(args)
    except ValueError as error:
        parser.error(str(error))

    return args


def is_information_command(args: argparse.Namespace) -> bool:
    """Return True when the CLI should print information and exit."""
    return bool(
        getattr(args, "list_port_profiles", False)
        or getattr(args, "list_stances", False)
        or getattr(args, "list_scan_profiles", False)
    )


def is_nmap_xml_import_command(args: argparse.Namespace) -> bool:
    """Return True when the CLI should import an existing Nmap XML file."""
    return bool(getattr(args, "nmap_xml", None))


def resolve_target_argument(args: argparse.Namespace) -> str:
    """Resolve exactly one positional or explicit CLI target."""
    positional_target = getattr(args, "target", None)
    explicit_target = getattr(args, "target_url", None)

    if positional_target and explicit_target:
        raise ValueError(
            "Provide the target either positionally or with -u/--url, not both."
        )

    if not positional_target and not explicit_target:
        raise ValueError(
            "A target is required. Provide it positionally or with -u/--url."
        )

    return explicit_target or positional_target


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
    port_profile = getattr(args, "port_profile", None)

    if args.ports and args.top_ports:
        raise ValueError("Use either --ports or --top-ports, not both.")

    if port_profile and args.ports:
        raise ValueError("Use either --port-profile or --ports, not both.")

    if port_profile and args.top_ports:
        raise ValueError("Use either --port-profile or --top-ports, not both.")

    if port_profile:
        return list(resolve_port_profile(port_profile).ports)

    if args.ports:
        return parse_custom_ports(args.ports)

    if args.top_ports is not None:
        if args.top_ports < 1:
            raise ValueError("--top-ports must be greater than zero.")

        if args.top_ports > len(TOP_400_TCP_PORTS):
            raise ValueError(f"--top-ports cannot exceed {len(TOP_400_TCP_PORTS)}.")

        return TOP_400_TCP_PORTS[: args.top_ports]

    scan_profile = get_scan_profile(args)

    if scan_profile:
        return list(resolve_port_profile(scan_profile.port_profile).ports)

    return TOP_400_TCP_PORTS.copy()


def resolve_scan_scope_label(args: argparse.Namespace) -> str:
    """Return the final panel scan scope label for the selected port mode."""
    port_profile = getattr(args, "port_profile", None)

    if port_profile:
        return f"Port Profile: {format_port_profile_label(port_profile)}"

    if args.ports:
        return "Custom Port List"

    if args.top_ports:
        return "Selected Port List"

    scan_profile = get_scan_profile(args)

    if scan_profile:
        return f"Scan Profile: {scan_profile.name}"

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


def validate_http_status_code(status_code: int) -> int:
    """Validate an HTTP response status code."""
    if not 100 <= status_code <= 599:
        raise ValueError(f"Invalid HTTP status code: {status_code}")

    return status_code


def parse_http_status_range(status_range: str) -> list[int]:
    """Parse an inclusive HTTP status-code range."""
    if status_range.count("-") != 1:
        raise ValueError(f"Invalid HTTP status range: {status_range}")

    start_text, end_text = status_range.split("-", maxsplit=1)

    if not start_text.strip() or not end_text.strip():
        raise ValueError(f"Invalid HTTP status range: {status_range}")

    start_code = validate_http_status_code(int(start_text.strip()))
    end_code = validate_http_status_code(int(end_text.strip()))

    if start_code > end_code:
        raise ValueError("HTTP status range start cannot be greater than the end.")

    return list(range(start_code, end_code + 1))


def parse_match_codes(match_code: str | None) -> list[int] | None:
    """Parse and normalize the optional HTTP status-code report filter."""
    if match_code is None:
        return None

    parsed_codes: list[int] = []

    for chunk in match_code.split(","):
        item = chunk.strip()

        if not item:
            raise ValueError("--match-code cannot contain empty values.")

        try:
            if "-" in item:
                parsed_codes.extend(parse_http_status_range(item))
            else:
                parsed_codes.append(validate_http_status_code(int(item)))
        except ValueError as error:
            if str(error).startswith(("Invalid HTTP", "HTTP status range")):
                raise

            raise ValueError(f"Invalid HTTP status code: {item}") from error

    return sorted(set(parsed_codes))


def resolve_scan_stance(args: argparse.Namespace) -> ScanStance:
    """Resolve the selected scan stance and explicit CLI overrides."""
    scan_profile = get_scan_profile(args)
    explicit_stance = getattr(args, "stance", None)
    explicit_threads = (
        scan_profile.workers if scan_profile and not explicit_stance else None
    )
    explicit_timeout = (
        scan_profile.timeout if scan_profile and not explicit_stance else None
    )

    if args.threads is not None:
        explicit_threads = validate_threads(args.threads)

    if args.timeout is not None:
        explicit_timeout = validate_timeout(args.timeout)

    return resolve_stance(
        stance_value=(
            explicit_stance
            or (scan_profile.stance if scan_profile else DEFAULT_STANCE)
        ),
        explicit_workers=explicit_threads,
        explicit_timeout=explicit_timeout,
    )


def get_scan_profile(args: argparse.Namespace) -> ScanProfile | None:
    """Return the selected complete scan profile, if any."""
    profile_value = getattr(args, "scan_profile", None)
    return resolve_scan_profile(profile_value) if profile_value else None


def resolve_max_rate(args: argparse.Namespace) -> float | None:
    """Return explicit pacing or the selected profile default."""
    explicit_max_rate = getattr(args, "max_rate", None)

    if explicit_max_rate is not None:
        return validate_max_rate(explicit_max_rate)

    scan_profile = get_scan_profile(args)
    return scan_profile.max_rate if scan_profile else None


def resolve_host_discovery(args: argparse.Namespace) -> str | None:
    """Return explicit host discovery or the selected profile default."""
    explicit_discovery = getattr(args, "host_discovery", None)

    if explicit_discovery:
        return explicit_discovery

    scan_profile = get_scan_profile(args)
    return scan_profile.host_discovery if scan_profile else None


def resolve_http_probing(args: argparse.Namespace) -> bool:
    """Return explicit HTTP probing or the selected profile/default behavior."""
    explicit_http_probing = getattr(args, "http_probing", None)

    if explicit_http_probing is not None:
        return explicit_http_probing

    scan_profile = get_scan_profile(args)
    return scan_profile.http_probing if scan_profile else True


def has_explicit_stance(args: argparse.Namespace) -> bool:
    """Return True when the user explicitly selected a TCP scan stance."""
    return getattr(args, "stance", None) is not None


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
    ports = getattr(args, "ports", None)
    top_ports = getattr(args, "top_ports", None)
    port_profile = getattr(args, "port_profile", None)
    scan_profile = getattr(args, "scan_profile", None)
    match_code = getattr(args, "match_code", None)
    nmap_xml = getattr(args, "nmap_xml", None)
    nmap = getattr(args, "nmap", False)
    nmap_path = getattr(args, "nmap_path", None)
    subfinder_path = getattr(args, "subfinder_path", None)
    amass_path = getattr(args, "amass_path", None)
    httpx = getattr(args, "httpx", False)
    httpx_path = getattr(args, "httpx_path", None)
    host_discovery = getattr(args, "host_discovery", None)
    threads = getattr(args, "threads", None)
    timeout = getattr(args, "timeout", None)
    max_rate = getattr(args, "max_rate", None)
    http_probing = getattr(args, "http_probing", None)

    if passive_providers and (
        ports
        or top_ports
        or port_profile
        or scan_profile
        or match_code
        or host_discovery
        or http_probing is not None
    ):
        raise ValueError(
            "Use passive discovery provider flags or TCP scan/report flags, not both."
        )

    if nmap_path and not nmap:
        raise ValueError("Use --nmap-path only together with --nmap.")

    if httpx_path and not httpx:
        raise ValueError("Use --httpx-path only together with --httpx.")

    if httpx and not passive_providers:
        raise ValueError("Use --httpx with --subfinder and/or --amass.")

    if nmap:
        passive_flags = (
            passive_providers or subfinder_path or amass_path or httpx or httpx_path
        )

        if nmap_xml:
            raise ValueError("Use --nmap or --nmap-xml, not both.")

        if passive_flags:
            raise ValueError("Use --nmap with TCP scanning, not passive discovery.")

    if nmap_xml:
        passive_flags = (
            passive_providers or subfinder_path or amass_path or httpx or httpx_path
        )
        tcp_flags = ports or top_ports or port_profile or scan_profile or match_code
        tcp_tuning_flags = (
            threads is not None
            or timeout is not None
            or max_rate is not None
            or http_probing is not None
        )

        if passive_flags:
            raise ValueError("Use --nmap-xml or passive discovery flags, not both.")

        if tcp_flags or host_discovery:
            raise ValueError("Use --nmap-xml or TCP scan/report flags, not both.")

        if tcp_tuning_flags:
            raise ValueError("Use --nmap-xml or TCP scan tuning flags, not both.")

    if match_code and not resolve_http_probing(args):
        raise ValueError("Use --match-code only when HTTP probing is enabled.")


def resolve_port_profile_label(args: argparse.Namespace) -> str | None:
    """Return the selected port profile display label, if any."""
    port_profile = getattr(args, "port_profile", None)

    if not port_profile:
        return None

    return format_port_profile_label(port_profile)


def is_quiet_mode(args: argparse.Namespace) -> bool:
    """Return True when automation-friendly quiet output is enabled."""
    return bool(getattr(args, "quiet", False))
