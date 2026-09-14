#!/usr/bin/env python3
"""Main CLI orchestrator for hylianscan."""

from collections.abc import Mapping
from pathlib import Path

from core.banner import show_banner
from core.cli import (
    get_passive_providers,
    get_scan_profile,
    has_explicit_stance,
    is_quiet_mode,
    is_information_command,
    is_nmap_xml_import_command,
    parse_arguments,
    parse_match_codes,
    parse_ports_list,
    resolve_port_profile_label,
    resolve_host_discovery,
    resolve_http_probing,
    resolve_max_rate,
    resolve_scan_scope_label,
    resolve_scan_stance,
    validate_mode,
)
from core.colors import (
    ALERT_RED,
    INFO_BLUE,
    RESET,
    TRIFORCE_BLUE,
    TRIFORCE_GREEN,
    TRIFORCE_RED,
)
from core.info_commands import build_information_command_output
from core.nmap_live_display import NmapServiceScanDisplay
from core.output import (
    resolve_output_workspace,
    resolve_json_output_path,
    resolve_nmap_import_json_output_path,
    resolve_nmap_import_output_path,
    resolve_output_path,
    resolve_subdomain_json_output_path,
    resolve_subdomain_output_path,
    save_report,
    save_subdomain_results,
    should_create_passive_output_workspace,
    should_create_tcp_output_workspace,
)
from core.panel import (
    build_final_panel,
    build_quiet_final_panel,
    build_saved_text_report,
)
from core.passive_display import (
    PassiveDiscoveryDisplay,
    build_passive_subdomain_summary,
    format_relative_output_path,
    format_passive_provider_count_message,
    show_passive_providers,
)
from core.passive_telemetry import PassiveActivityTelemetry
from core.tcp_live_display import TCPScanDisplay
from core.terminal import (
    clear_dynamic_line,
    clear_screen,
    print_safe,
)
from modules.json_exporter import (
    write_nmap_xml_import_json_report,
    write_subdomain_json_report,
    write_tcp_json_report,
)
from modules.http_filter import (
    build_http_status_filter_metadata,
    filter_scan_result_by_http_status,
)
from modules.host_discovery import discover_hosts
from modules.httpx_runner import (
    HttpxResult,
    build_skipped_httpx_result,
    format_httpx_summary,
    run_httpx,
    write_httpx_jsonl,
)
from modules.nmap_enrichment import (
    NmapEnrichmentResult,
    build_completed_nmap_enrichment,
    build_skipped_nmap_enrichment,
)
from modules.nmap_runner import run_nmap_service_version_scan
from modules.nmap_xml import (
    format_nmap_xml_import_summary,
    parse_single_host_nmap_xml_file,
)
from modules.scan_stance import ScanStance
from modules.subdomain import run_amass, run_subfinder
from modules.target import TargetInfo, resolve_target
from modules.tcp_scanner import ScanResult, scan_tcp_ports


STANCE_ALIAS_COLORS = {
    "Din": TRIFORCE_RED,
    "Nayru": TRIFORCE_BLUE,
    "Farore": TRIFORCE_GREEN,
}


def has_scan_config_overrides(args: object) -> bool:
    """Return True when explicit TCP controls override scan defaults."""
    return any(
        getattr(args, attribute, None) is not None
        for attribute in (
            "ports",
            "top_ports",
            "port_profile",
            "stance",
            "threads",
            "timeout",
            "max_rate",
            "host_discovery",
            "http_probing",
        )
    )


def format_scan_config_source(
    has_overrides: bool,
    scan_profile_name: str | None = None,
) -> str:
    """Return a short label explaining how the effective scan config was chosen."""
    if scan_profile_name and has_overrides:
        return f"Scan Profile: {scan_profile_name} + User Overrides"

    if scan_profile_name:
        return f"Scan Profile: {scan_profile_name}"

    if has_overrides:
        return "User Overrides"

    return "Default Scan Values"


def format_max_rate_label(max_rate: float | None) -> str:
    """Return the display label for optional TCP connection start pacing."""
    if max_rate is None:
        return "Unlimited"

    return f"{max_rate:g}/s"


def format_match_codes(match_codes: list[int]) -> str:
    """Return a readable HTTP status-code filter label."""
    return ", ".join(str(status_code) for status_code in match_codes)


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
    max_rate: float | None = None,
    has_overrides: bool = False,
    show_stance: bool = True,
    nmap_enabled: bool = False,
    port_profile_label: str | None = None,
    match_codes: list[int] | None = None,
    host_discovery: str | None = None,
    scan_profile_name: str | None = None,
    http_probing: bool = True,
) -> None:
    """Render the target orientation and effective scan configuration block."""
    alias_color = STANCE_ALIAS_COLORS.get(stance.lore_alias, INFO_BLUE)
    label_width = 14
    lines = ["[*] Target Orientation:"]

    lines.extend(
        [
            f"{'Host':<{label_width}}: {target.target_host}",
            f"{'Resolved IP':<{label_width}}: {target.resolved_ip}",
        ]
    )

    if target.addresses:
        lines.append(f"{'Address Mode':<{label_width}}: {target.address_family}")

        if target.ipv4_addresses:
            lines.append(
                f"{'IPv4 Addresses':<{label_width}}: "
                f"{', '.join(address.address for address in target.ipv4_addresses)}"
            )

        if target.ipv6_addresses:
            lines.append(
                f"{'IPv6 Addresses':<{label_width}}: "
                f"{', '.join(address.address for address in target.ipv6_addresses)}"
            )

        reverse_dns = [
            f"{address.address} -> {address.reverse_dns}"
            for address in target.address_records
            if address.reverse_dns
        ]
        if reverse_dns:
            lines.append(f"{'Reverse DNS':<{label_width}}: {'; '.join(reverse_dns)}")

    if host_discovery:
        lines.append(f"{'Host Discovery':<{label_width}}: {host_discovery}")

    if show_stance:
        lines.append(
            f"{'Stance':<{label_width}}: {stance.name} "
            f"({alias_color}{stance.lore_alias}{RESET}{INFO_BLUE})"
        )

    lines.extend(
        [
            f"{'Workers':<{label_width}}: {stance.workers}",
            f"{'Timeout':<{label_width}}: {stance.timeout:.2f}s",
            f"{'Max Rate':<{label_width}}: {format_max_rate_label(max_rate)}",
            (
                f"{'Config Source':<{label_width}}: "
                f"{format_scan_config_source(has_overrides, scan_profile_name)}"
            ),
            f"{'HTTP Probing':<{label_width}}: {'Enabled' if http_probing else 'Disabled'}",
        ]
    )

    if nmap_enabled:
        lines.append("Nmap Enrichment : Enabled (post-scan)")

    lines.append(f"{'Scan Phase':<{label_width}}: Hylian TCP Connect Scan")

    if port_profile_label:
        lines.append(f"{'Port Profile':<{label_width}}: {port_profile_label}")

    if match_codes is not None:
        lines.append(
            f"{'HTTP Filter':<{label_width}}: Status codes "
            f"{format_match_codes(match_codes)}"
        )

    lines.append(f"{'Port Scope':<{label_width}}: {port_count} ports")

    print()
    print(f"{INFO_BLUE}{chr(10).join(lines)}{RESET}")
    print()


def run_port_scan(
    target: TargetInfo,
    ports_to_scan: list[int],
    timeout: float,
    max_workers: int,
    max_rate: float | None = None,
    quiet: bool = False,
    http_probing: bool = True,
) -> ScanResult:
    """Run the threaded TCP scanner without embedding TCP logic in the CLI."""
    display = None if quiet else TCPScanDisplay(target, len(ports_to_scan))

    if display is not None:
        display.start_connect_scan()

    scanner_arguments = {
        "target_host": target.target_host,
        "resolved_ip": target.resolved_ip,
        "ports": ports_to_scan,
        "timeout": timeout,
        "max_workers": max_workers,
        "max_rate": max_rate,
        "http_probing": http_probing,
        "progress_callback": None if display is None else display.handle_progress,
        "open_port_callback": None if display is None else display.handle_open_port,
        "service_probe_start_callback": (
            None if display is None else display.start_service_probe
        ),
        "service_probe_complete_callback": (
            None if display is None else display.complete_service_probe
        ),
    }

    if target.addresses:
        scanner_arguments["addresses"] = target.address_records

    result = scan_tcp_ports(
        **scanner_arguments,
    )

    if display is not None:
        clear_dynamic_line()

    return result


def run_host_discovery(
    target: TargetInfo,
    method: str,
    timeout: float,
) -> TargetInfo:
    """Run optional host discovery and retain only reachable addresses."""
    discovery_results = discover_hosts(
        target.address_records,
        method,
        timeout=timeout,
    )
    reachable_addresses = tuple(
        result.address for result in discovery_results if result.is_up
    )

    if not reachable_addresses:
        errors = "; ".join(
            result.error or f"{result.address.address} did not respond"
            for result in discovery_results
        )
        raise ValueError(f"Host discovery found no reachable addresses: {errors}")

    return target.with_addresses(reachable_addresses)


def run_passive_subdomain_discovery(
    domain: str,
    providers: list[str],
    output_path: Path,
    json_output_path: Path | None = None,
    provider_paths: Mapping[str, str | None] | None = None,
    httpx_enabled: bool = False,
    httpx_binary: str | None = None,
    quiet: bool = False,
) -> str:
    """Run selected passive discovery providers and return a clean summary."""
    telemetry = None if quiet else PassiveActivityTelemetry()
    display = None if quiet else PassiveDiscoveryDisplay(domain)
    provider_results: dict[str, list[str]] = {}
    subdomains: list[str] = []
    httpx_result: HttpxResult | None = None
    httpx_output_path: Path | None = None
    executable_paths = provider_paths or {}

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
                    executable_path=executable_paths.get("subfinder"),
                )
            elif provider == "amass":
                provider_results[provider] = run_amass(
                    domain,
                    telemetry_callback=telemetry_callback,
                    executable_path=executable_paths.get("amass"),
                )

            if display is not None:
                display.add_activity(
                    format_passive_provider_count_message(
                        provider,
                        len(provider_results[provider]),
                    )
                )

        if display is not None and telemetry is not None:
            display.add_activity(telemetry.map_merge_activity())
            display.add_activity("[*] Removing duplicate subdomains...")

        subdomains = merge_subdomain_results(provider_results)
        raw_discovery_count = sum(len(results) for results in provider_results.values())

        if display is not None:
            display.add_activity("[*] Writing passive discovery output...")

        save_subdomain_results(subdomains, output_path)

        if httpx_enabled:
            httpx_targets = [domain, *subdomains]
            if display is not None:
                display.add_activity(
                    f"[*] Probing {len(httpx_targets)} web targets with HTTPx..."
                )

            try:
                httpx_arguments = {}
                if httpx_binary:
                    httpx_arguments["httpx_binary"] = httpx_binary
                httpx_result = run_httpx(httpx_targets, **httpx_arguments)
            except (RuntimeError, ValueError) as error:
                httpx_result = build_skipped_httpx_result(httpx_targets, str(error))

            if httpx_result.status == "completed":
                httpx_output_path = output_path.with_name("httpx.jsonl")
                write_httpx_jsonl(httpx_result, httpx_output_path)

            if display is not None:
                display.add_activity(
                    f"[+] HTTPx returned {len(httpx_result.findings)} live services"
                )

        if json_output_path is not None:
            write_subdomain_json_report(
                target_domain=domain,
                provider_results=provider_results,
                output_path=json_output_path,
                httpx_result=httpx_result,
            )
    finally:
        if display is not None:
            display.stop()

    if not subdomains and not quiet:
        print_safe(
            f"{ALERT_RED}[-] No passive subdomains were returned by selected providers.{RESET}"
        )

    summary = build_passive_subdomain_summary(
        domain,
        raw_discovery_count,
        len(subdomains),
        output_path,
        quiet,
    )

    if httpx_result is not None:
        display_path = (
            format_relative_output_path(httpx_output_path)
            if httpx_output_path is not None
            else None
        )
        summary = "\n\n".join(
            [summary, format_httpx_summary(httpx_result, display_path)]
        )

    return summary


def run_nmap_xml_import(
    xml_path: str,
    output_path: Path | None = None,
    json_output_path: Path | None = None,
) -> str:
    """Import an existing Nmap XML file and return a plain summary."""
    import_result = parse_single_host_nmap_xml_file(xml_path)
    summary = format_nmap_xml_import_summary(import_result, xml_path)
    save_report(summary, output_path)

    if json_output_path is not None:
        write_nmap_xml_import_json_report(import_result, xml_path, json_output_path)

    return summary


def run_live_nmap_enrichment(
    target: TargetInfo,
    scan_result: ScanResult,
    nmap_binary: str | None = None,
) -> NmapEnrichmentResult:
    """Run optional Nmap service enrichment against native open TCP ports."""
    open_ports = [finding.port for finding in scan_result.open_ports]

    if not open_ports:
        return build_skipped_nmap_enrichment(
            "no open TCP ports found.",
            target.resolved_ip,
            open_ports,
        )

    try:
        keyword_arguments = {}

        if nmap_binary:
            keyword_arguments["nmap_binary"] = nmap_binary

        import_result = run_nmap_service_version_scan(
            target.resolved_ip,
            open_ports,
            **keyword_arguments,
        )

        return build_completed_nmap_enrichment(
            import_result,
            target.resolved_ip,
            open_ports,
        )
    except (RuntimeError, ValueError) as error:
        return build_skipped_nmap_enrichment(
            str(error),
            target.resolved_ip,
            open_ports,
        )


def main() -> None:
    """Coordinate the full CLI execution flow."""
    quiet = False

    try:
        args = parse_arguments()
        quiet = is_quiet_mode(args)

        if is_information_command(args):
            print(build_information_command_output(args))
            return

        validate_mode(args)

        if is_nmap_xml_import_command(args):
            output_path = resolve_nmap_import_output_path(args.output)
            json_output_path = resolve_nmap_import_json_output_path(args.json_output)
            print(
                run_nmap_xml_import(
                    args.nmap_xml,
                    output_path=output_path,
                    json_output_path=json_output_path,
                )
            )
            return

        if not quiet:
            clear_screen()
            show_banner()

        passive_providers = get_passive_providers(args)

        if passive_providers:
            workspace_dir = (
                resolve_output_workspace(args.target)
                if should_create_passive_output_workspace(args.output, args.json_output)
                else None
            )
            output_path = resolve_subdomain_output_path(
                args.output,
                workspace_dir=workspace_dir,
            )
            json_output_path = resolve_subdomain_json_output_path(
                args.json_output,
                workspace_dir=workspace_dir,
            )

            if not quiet:
                show_passive_providers(passive_providers)

            final_panel = run_passive_subdomain_discovery(
                domain=args.target,
                providers=passive_providers,
                output_path=output_path,
                json_output_path=json_output_path,
                provider_paths={
                    "subfinder": args.subfinder_path,
                    "amass": args.amass_path,
                },
                httpx_enabled=getattr(args, "httpx", False),
                httpx_binary=getattr(args, "httpx_path", None),
                quiet=quiet,
            )
            print(final_panel)
        else:
            workspace_dir = (
                resolve_output_workspace(args.target)
                if should_create_tcp_output_workspace(args.output, args.json_output)
                else None
            )
            output_path = resolve_output_path(args.output, workspace_dir=workspace_dir)
            json_output_path = resolve_json_output_path(
                args.json_output,
                workspace_dir=workspace_dir,
            )
            ports_to_scan = parse_ports_list(args)
            match_code_expression = getattr(args, "match_code", None)
            match_codes = parse_match_codes(match_code_expression)
            report_filters = build_http_status_filter_metadata(
                match_code_expression,
                match_codes,
            )
            scan_stance = resolve_scan_stance(args)
            scan_profile = get_scan_profile(args)
            max_rate = resolve_max_rate(args)
            http_probing = resolve_http_probing(args)
            has_overrides = has_scan_config_overrides(args)
            scan_scope = resolve_scan_scope_label(args)
            port_profile_label = resolve_port_profile_label(args)
            target = resolve_target(
                args.target,
                address_family=getattr(args, "address_family", "dual-stack"),
            )
            host_discovery = resolve_host_discovery(args)

            if host_discovery:
                target = run_host_discovery(
                    target,
                    host_discovery,
                    scan_stance.timeout,
                )

            if not quiet:
                show_target_orientation(
                    target,
                    scan_stance,
                    len(ports_to_scan),
                    max_rate=max_rate,
                    has_overrides=has_overrides,
                    show_stance=has_explicit_stance(args) or scan_profile is not None,
                    nmap_enabled=getattr(args, "nmap", False),
                    port_profile_label=port_profile_label,
                    match_codes=match_codes,
                    host_discovery=host_discovery,
                    scan_profile_name=(scan_profile.name if scan_profile else None),
                    http_probing=http_probing,
                )

            native_scan_result = run_port_scan(
                target=target,
                ports_to_scan=ports_to_scan,
                timeout=scan_stance.timeout,
                max_workers=scan_stance.workers,
                max_rate=max_rate,
                quiet=quiet,
                http_probing=http_probing,
            )
            scan_result = filter_scan_result_by_http_status(
                native_scan_result,
                match_codes,
            )

            if quiet and match_codes is not None:
                print(f"HTTP Status Filter: {format_match_codes(match_codes)}")

            if quiet:
                final_panel = build_quiet_final_panel(
                    scan_result,
                    scan_scope=scan_scope,
                )
            else:
                final_panel = build_final_panel(
                    scan_result,
                    scan_scope=scan_scope,
                )

            print(final_panel)
            nmap_enrichment = None

            if getattr(args, "nmap", False):
                nmap_display = (
                    None
                    if quiet or not native_scan_result.open_ports
                    else NmapServiceScanDisplay(
                        target.resolved_ip,
                        [finding.port for finding in native_scan_result.open_ports],
                    )
                )

                if nmap_display is not None:
                    nmap_display.start()

                try:
                    nmap_enrichment = run_live_nmap_enrichment(
                        target,
                        native_scan_result,
                        getattr(args, "nmap_path", None),
                    )
                finally:
                    if nmap_display is not None:
                        nmap_display.stop()

            saved_report = build_saved_text_report(
                scan_result,
                scan_scope=scan_scope,
                base_report=final_panel,
                match_code_expression=match_code_expression,
            )

            if nmap_enrichment is not None:
                saved_report = "\n\n".join(
                    [saved_report, nmap_enrichment.terminal_text]
                )

            save_report(saved_report, output_path)

            if json_output_path is not None:
                write_tcp_json_report(
                    scan_result,
                    json_output_path,
                    report_filters=report_filters,
                    nmap_enrichment=nmap_enrichment,
                )

            if output_path is not None and not quiet:
                print_safe(f"[*] Report saved to: {output_path}")

            if nmap_enrichment is not None:
                print()
                print(nmap_enrichment.terminal_text)

    except ValueError as error:
        if quiet:
            print(f"Error: {error}")
        else:
            print(f"\n{ALERT_RED}[-] {error}{RESET}")
        raise SystemExit(1) from error

    except KeyboardInterrupt:
        if quiet:
            print("Scan aborted. Exiting safely.")
        else:
            clear_dynamic_line()
            print(f"\n{INFO_BLUE}[-] Scan aborted by {ALERT_RED}Ganondorf{INFO_BLUE}. Exiting safely.{RESET}")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
