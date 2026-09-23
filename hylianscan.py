#!/usr/bin/env python3
"""Main CLI orchestrator for hylianscan."""

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
import sys
import time

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
    resolve_subdomain_candidates_path,
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
    show_passive_providers,
)
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
from modules.host_discovery import HostDiscoveryResult, discover_hosts
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
    build_multi_nmap_enrichment,
    build_skipped_nmap_enrichment,
)
from modules.nmap_runner import run_nmap_service_version_scan
from modules.nmap_xml import (
    format_nmap_xml_import_summary,
    parse_single_host_nmap_xml_file,
)
from modules.scan_stance import ScanStance
from modules.subdomain import (
    DEFAULT_PROVIDER_TIMEOUT_SECONDS, ProviderInterrupted, ProviderRunResult,
    inspect_provider_compatibility, resolve_provider_executable,
    run_amass, run_dnsx, run_subfinder, scoped_subdomain,
)
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


def merge_subdomain_results(
    provider_results: Mapping[str, ProviderRunResult],
) -> list[str]:
    """Merge provider results into one deduplicated and sorted subdomain list."""
    return sorted(
        {
            subdomain.strip().lower().strip(".")
            for result in provider_results.values()
            for subdomain in result.subdomains
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
) -> tuple[TargetInfo, tuple[HostDiscoveryResult, ...]]:
    """Run host discovery and return the scan target plus its evidence."""
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

    return target.with_addresses(reachable_addresses), discovery_results


def run_passive_subdomain_discovery(
    domain: str,
    providers: list[str],
    output_path: Path,
    json_output_path: Path | None = None,
    provider_paths: Mapping[str, str | None] | None = None,
    address_family: str = "dual-stack",
    dnsx_resolver: str | None = None,
    dnsx_threads: int | None = None,
    dnsx_rate_limit: int | None = None,
    dnsx_timeout: float | None = None,
    dnsx_retry: int | None = None,
    dnsx_auto_wildcard: bool = False,
    dnsx_json: bool = False,
    httpx_enabled: bool = False,
    httpx_binary: str | None = None,
    quiet: bool = False,
    provider_timeouts: Mapping[str, float | None] | None = None,
    verbose: bool = False,
    debug: bool = False,
) -> str:
    """Run selected passive discovery providers and return a clean summary."""
    if scoped_subdomain(domain, domain) is None:
        raise ValueError("Passive discovery requires a valid DNS domain name.")
    if not quiet:
        show_passive_providers(providers)
    executable_paths = provider_paths or {}
    executables = {}
    for provider in providers:
        executables[provider] = resolve_provider_executable(
            provider_name={"subfinder": "Subfinder", "amass": "Amass", "dnsx": "DNSx"}[provider],
            default_command=provider,
            path_option=f"--{provider}-path",
            explicit_path=executable_paths.get(provider),
        )
    timeouts = dict.fromkeys(providers, DEFAULT_PROVIDER_TIMEOUT_SECONDS)
    timeouts.update({name: value for name, value in (provider_timeouts or {}).items()
                     if value is not None})
    compatibility = {}
    for provider in providers:
        started = time.monotonic()
        compatibility[provider] = inspect_provider_compatibility(
            provider, executables[provider], timeout=min(timeouts[provider], 10.0),
        )
        timeouts[provider] -= time.monotonic() - started
        if timeouts[provider] <= 0:
            raise ValueError(f"{provider} process budget exhausted during compatibility checks.")
        if compatibility[provider]["status"] != "tested":
            reason = compatibility[provider].get("reason", "Output compatibility is unverified.")
            print(f"Warning: {provider} {compatibility[provider]['version']} is "
                  f"{compatibility[provider]['status']}; {reason}", file=sys.stderr)
    display = None if quiet else PassiveDiscoveryDisplay()
    provider_results = {
        provider: ProviderRunResult([], "skipped", reason="Provider has not started.")
        for provider in providers
    }
    subdomains: list[str] = []
    httpx_result: HttpxResult | None = None
    httpx_output_path: Path | None = None
    discovery_providers = [provider for provider in providers if provider != "dnsx"]
    provider = ""

    def save_progress() -> list[str]:
        for name, result in provider_results.items():
            provider_results[name] = replace(result, compatibility=compatibility[name])
        candidates = merge_subdomain_results({
            name: provider_results[name] for name in discovery_providers
        })
        candidates = [name for name in candidates if scoped_subdomain(name, domain)]
        if "dnsx" in providers:
            save_subdomain_results(candidates, resolve_subdomain_candidates_path(output_path))
            final = provider_results["dnsx"].subdomains
        else:
            final = candidates
        save_subdomain_results(final, output_path)
        if json_output_path is not None:
            write_subdomain_json_report(
                domain, provider_results, json_output_path, final_subdomains=final,
                httpx_result=httpx_result,
            )
        diagnostics = [
            f"{name}: {line}" for name, result in provider_results.items()
            for line in result.diagnostics
        ]
        if diagnostics:
            save_report("\n".join(diagnostics), output_path.with_name(f"{output_path.stem}_providers.log"))
        return final

    def handle_provider_output(output: str) -> None:
        if display is None:
            return
        if " progress: " in output:
            try:
                count = int(output.rsplit("; ", 1)[1].split(" ", 1)[0])
            except (IndexError, ValueError):
                pass
            else:
                display.update_count(count)
        if verbose or debug:
            print_safe(f"[i] {output}")

    try:
        for provider in discovery_providers:
            telemetry_callback = handle_provider_output if display is not None else None
            if display is not None:
                display.start_provider(provider)

            if provider == "subfinder":
                provider_results[provider] = run_subfinder(
                    domain,
                    telemetry_callback=telemetry_callback,
                    executable_path=executable_paths.get("subfinder"),
                    timeout=timeouts[provider],
                )
            elif provider == "amass":
                provider_results[provider] = run_amass(
                    domain,
                    telemetry_callback=telemetry_callback,
                    executable_path=executable_paths.get("amass"),
                    timeout=timeouts[provider],
                )

            if display is not None:
                display.finish_provider(
                    provider_results[provider].status,
                    len(provider_results[provider].subdomains),
                )

            save_progress()

        if "dnsx" in providers:
            provider = "dnsx"
            if display is not None:
                display.start_provider(provider)
            candidate_subdomains = [name for name in merge_subdomain_results(provider_results)
                                    if scoped_subdomain(name, domain)]
            telemetry_callback = handle_provider_output if display is not None else None

            provider_results["dnsx"] = run_dnsx(
                candidate_subdomains,
                telemetry_callback=telemetry_callback,
                executable_path=executable_paths.get("dnsx"),
                timeout=timeouts[provider],
                address_family=address_family,
                resolver=dnsx_resolver,
                threads=dnsx_threads,
                rate_limit=dnsx_rate_limit,
                query_timeout=dnsx_timeout,
                retry=dnsx_retry,
                auto_wildcard=dnsx_auto_wildcard,
                json_output=dnsx_json,
            )

            if display is not None:
                display.finish_provider(
                    provider_results["dnsx"].status,
                    len(provider_results["dnsx"].subdomains),
                )

        subdomains = save_progress()

        raw_discovery_count = sum(
            len(provider_results[provider].subdomains)
            for provider in discovery_providers
        )

        if httpx_enabled:
            provider = "httpx"
            httpx_targets = [domain, *subdomains]
            if display is not None:
                display.start_provider("httpx")

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
                display.finish_provider(
                    httpx_result.status,
                    len(httpx_result.findings),
                )

            save_progress()
    except (KeyboardInterrupt, ValueError) as error:
        if isinstance(error, ProviderInterrupted):
            provider_results[provider] = error.result
        elif provider in provider_results and provider_results[provider].status == "skipped":
            provider_results[provider] = ProviderRunResult(
                [], "interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                reason=str(error) or "Interrupted by user.",
            )
        if display is not None and provider in provider_results and provider_results[provider].status != "completed":
            display.finish_provider(
                provider_results[provider].status,
                len(provider_results[provider].subdomains),
            )
        elif display is not None and provider == "httpx":
            display.finish_provider(
                "interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                len(httpx_result.findings) if httpx_result is not None else 0,
            )
        save_progress()
        raise
    finally:
        if display is not None:
            display.stop()

    provider_failures = [
        f"{provider}: {result.reason or result.status}"
        for provider, result in provider_results.items()
        if result.status in {"failed", "timed_out"}
    ]

    if provider_failures:
        raise ValueError(
            "Passive discovery completed with provider errors: "
            f"{'; '.join(provider_failures)} Partial results were saved."
        )

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
    findings_by_address: dict[str, list[int]] = {}

    for finding in scan_result.open_ports:
        address = finding.address or target.resolved_ip
        findings_by_address.setdefault(address, []).append(finding.port)

    if not findings_by_address:
        return build_skipped_nmap_enrichment(
            "no open TCP ports found.",
            target.resolved_ip,
            [],
        )

    runs = []

    for address, open_ports in findings_by_address.items():
        try:
            keyword_arguments = {}

            if nmap_binary:
                keyword_arguments["nmap_binary"] = nmap_binary

            import_result = run_nmap_service_version_scan(
                address,
                open_ports,
                **keyword_arguments,
            )

            runs.append(
                build_completed_nmap_enrichment(
                    import_result,
                    address,
                    open_ports,
                )
            )
        except (RuntimeError, ValueError) as error:
            runs.append(
                build_skipped_nmap_enrichment(
                    str(error),
                    address,
                    open_ports,
                )
            )

    return build_multi_nmap_enrichment(target.target_host, runs)


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

            final_panel = run_passive_subdomain_discovery(
                domain=args.target,
                providers=passive_providers,
                output_path=output_path,
                json_output_path=json_output_path,
                provider_paths={
                    "subfinder": getattr(args, "subfinder_path", None),
                    "amass": getattr(args, "amass_path", None),
                    "dnsx": getattr(args, "dnsx_path", None),
                },
                provider_timeouts={
                    "subfinder": getattr(args, "subfinder_timeout", None),
                    "amass": getattr(args, "amass_timeout", None),
                    "dnsx": getattr(args, "dnsx_process_timeout", None),
                },
                address_family=getattr(args, "address_family", "dual-stack"),
                dnsx_resolver=getattr(args, "dnsx_resolver", None),
                dnsx_threads=getattr(args, "dnsx_threads", None),
                dnsx_rate_limit=getattr(args, "dnsx_rate_limit", None),
                dnsx_timeout=getattr(args, "dnsx_timeout", None),
                dnsx_retry=getattr(args, "dnsx_retry", None),
                dnsx_auto_wildcard=getattr(args, "dnsx_auto_wildcard", False),
                dnsx_json=getattr(args, "dnsx_json", False),
                httpx_enabled=getattr(args, "httpx", False),
                httpx_binary=getattr(args, "httpx_path", None),
                quiet=quiet,
                verbose=getattr(args, "verbose", False),
                debug=getattr(args, "debug", False),
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
            host_discovery_results = None

            if host_discovery:
                target, host_discovery_results = run_host_discovery(
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
            filtered_scan_result = filter_scan_result_by_http_status(
                native_scan_result,
                match_codes,
            )
            http_status_filter = (
                format_match_codes(match_codes) if match_codes is not None else None
            )
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

            if quiet:
                final_panel = build_quiet_final_panel(
                    filtered_scan_result,
                    scan_scope=scan_scope,
                    native_open_port_count=len(native_scan_result.open_ports),
                    http_status_filter=http_status_filter,
                )
            else:
                final_panel = build_final_panel(
                    filtered_scan_result,
                    scan_scope=scan_scope,
                    native_open_port_count=len(native_scan_result.open_ports),
                    http_status_filter=http_status_filter,
                )

            terminal_report = final_panel

            if nmap_enrichment is not None:
                terminal_report = "\n\n".join(
                    [terminal_report, nmap_enrichment.terminal_text]
                )

            print(terminal_report)

            saved_report = build_saved_text_report(
                filtered_scan_result,
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
                    filtered_scan_result,
                    json_output_path,
                    report_filters=report_filters,
                    nmap_enrichment=nmap_enrichment,
                    native_open_port_count=len(native_scan_result.open_ports),
                    host_discovery_results=host_discovery_results,
                )

            if output_path is not None and not quiet:
                print_safe(f"[*] Report saved to: {output_path}")

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
