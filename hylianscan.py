#!/usr/bin/env python3
"""Main CLI orchestrator for the hylianscan v1.0 development release."""

from collections.abc import Mapping
from pathlib import Path

from core.banner import show_banner
from core.cli import (
    get_passive_providers,
    is_quiet_mode,
    is_information_command,
    is_nmap_xml_import_command,
    parse_arguments,
    parse_match_codes,
    parse_ports_list,
    resolve_port_profile_label,
    resolve_scan_scope_label,
    resolve_scan_stance,
    validate_max_rate,
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
from modules.nmap_enrichment import (
    format_nmap_enrichment_skipped,
    format_nmap_enrichment_summary,
)
from modules.nmap_runner import run_nmap_service_version_scan
from modules.nmap_xml import (
    format_nmap_xml_import_summary,
    parse_single_host_nmap_xml_file,
)
from modules.scan_stance import ScanStance
from modules.subdomain import run_amass, run_subfinder
from modules.target import TargetInfo, TargetResolutionError, resolve_target
from modules.tcp_scanner import ScanResult, scan_tcp_ports


STANCE_ALIAS_COLORS = {
    "Din": TRIFORCE_RED,
    "Nayru": TRIFORCE_BLUE,
    "Farore": TRIFORCE_GREEN,
}


def format_scan_stance_label(stance: ScanStance) -> str:
    """Return the display label for the active TCP scan stance."""
    alias_color = STANCE_ALIAS_COLORS.get(stance.lore_alias, INFO_BLUE)
    return f"{stance.name} ({alias_color}{stance.lore_alias}{RESET})"


def has_scan_config_overrides(args: object) -> bool:
    """Return True when explicit TCP scan controls override stance defaults."""
    return any(
        getattr(args, attribute, None) is not None
        for attribute in ("threads", "timeout", "max_rate")
    )


def format_scan_config_source(has_overrides: bool) -> str:
    """Return a short label explaining how the effective scan config was chosen."""
    if has_overrides:
        return "User Overrides"

    return "Default Stance Values"


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
    port_profile_label: str | None = None,
    match_codes: list[int] | None = None,
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
            f"{'Max Rate':<{label_width}}: {format_max_rate_label(max_rate)}",
            (
                f"{'Config Source':<{label_width}}: "
                f"{format_scan_config_source(has_overrides)}"
            ),
            f"{'Scan Phase':<{label_width}}: Hylian TCP Connect Scan",
            *(
                [f"{'Port Profile':<{label_width}}: {port_profile_label}"]
                if port_profile_label
                else []
            ),
            *(
                [
                    f"{'HTTP Filter':<{label_width}}: Status codes "
                    f"{format_match_codes(match_codes)}"
                ]
                if match_codes is not None
                else []
            ),
            f"{'Port Scope':<{label_width}}: {port_count} ports",
        ]
    )

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


def run_passive_subdomain_discovery(
    domain: str,
    providers: list[str],
    output_path: Path,
    json_output_path: Path | None = None,
    provider_paths: Mapping[str, str | None] | None = None,
    quiet: bool = False,
) -> str:
    """Run selected passive discovery providers and return a clean summary."""
    telemetry = None if quiet else PassiveActivityTelemetry()
    display = None if quiet else PassiveDiscoveryDisplay(domain)
    provider_results: dict[str, list[str]] = {}
    subdomains: list[str] = []
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

    return build_passive_subdomain_summary(
        domain,
        raw_discovery_count,
        len(subdomains),
        output_path,
        quiet,
    )


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
) -> str:
    """Run optional Nmap service enrichment against native open TCP ports."""
    open_ports = [finding.port for finding in scan_result.open_ports]

    if not open_ports:
        return format_nmap_enrichment_skipped("no open TCP ports found.")

    try:
        keyword_arguments = {}

        if nmap_binary:
            keyword_arguments["nmap_binary"] = nmap_binary

        import_result = run_nmap_service_version_scan(
            target.resolved_ip,
            open_ports,
            **keyword_arguments,
        )
    except (RuntimeError, ValueError) as error:
        return format_nmap_enrichment_skipped(str(error))

    return format_nmap_enrichment_summary(
        import_result,
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
            max_rate = validate_max_rate(args.max_rate)
            has_overrides = has_scan_config_overrides(args)
            scan_scope = resolve_scan_scope_label(args)
            port_profile_label = resolve_port_profile_label(args)
            target = resolve_target(args.target)

            if not quiet:
                show_target_orientation(
                    target,
                    scan_stance,
                    len(ports_to_scan),
                    max_rate=max_rate,
                    has_overrides=has_overrides,
                    port_profile_label=port_profile_label,
                    match_codes=match_codes,
                )

            native_scan_result = run_port_scan(
                target=target,
                ports_to_scan=ports_to_scan,
                timeout=scan_stance.timeout,
                max_workers=scan_stance.workers,
                max_rate=max_rate,
                quiet=quiet,
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
                    scan_stance=format_scan_stance_label(scan_stance),
                )

            print(final_panel)
            saved_report = build_saved_text_report(
                scan_result,
                scan_scope=scan_scope,
                scan_stance=None if quiet else format_scan_stance_label(scan_stance),
                base_report=final_panel,
                match_code_expression=match_code_expression,
            )
            save_report(saved_report, output_path)

            if json_output_path is not None:
                write_tcp_json_report(
                    scan_result,
                    json_output_path,
                    report_filters=report_filters,
                )

            if output_path is not None and not quiet:
                print_safe(f"[*] Report saved to: {output_path}")

            if getattr(args, "nmap", False):
                print()
                print(
                    run_live_nmap_enrichment(
                        target,
                        native_scan_result,
                        getattr(args, "nmap_path", None),
                    )
                )

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
