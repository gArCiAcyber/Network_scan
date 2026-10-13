"""Human-readable TCP reports; full protocol evidence lives in JSON."""

import sys

from core.colors import (
    BOLD_GOLD,
    BRIGHT_WHITE,
    GREEN,
    MUTED_GRAY,
    RESET,
    WARNING_YELLOW,
)
from core.terminal import escape_controls, format_separator, wrap_report
from modules.tcp_scanner import PortScanResult, ScanResult


def get_triforce_symbol() -> str:
    """Return a terminal-safe Triforce symbol."""
    try:
        "\u25b2".encode(sys.stdout.encoding or "utf-8")
    except UnicodeEncodeError:
        return "^"
    return "\u25b2"


def format_panel_title() -> str:
    return (
        f"{GREEN}[ SCAN BY THE {BOLD_GOLD}TRIFORCE {get_triforce_symbol()}"
        f"{RESET}{GREEN} ]{RESET}"
    )


def format_finding_address(finding: PortScanResult) -> str | None:
    address = getattr(finding, "address", None)
    if not address:
        return None
    if getattr(finding, "scope_id", 0) and "%" not in address:
        address = f"{address}%{finding.scope_id}"
    return escape_controls(address)


def scan_addresses(summary: ScanResult) -> list[str]:
    """Retain IPv6 scope IDs and legacy callers' address lists."""
    addresses = getattr(summary, "addresses", ())
    if addresses:
        return [escape_controls(
            f"{a.address}%{a.scope_id}" if a.scope_id and "%" not in a.address else a.address
        ) for a in addresses]
    return [escape_controls(a) for a in (
        getattr(summary, "resolved_ips", ()) or (summary.resolved_ip,)
    )]


def build_report_lines(
    summary: ScanResult,
    scan_scope: str,
    native_open_port_count: int | None,
    http_status_filter: str | None,
    *,
    quiet: bool = False,
) -> list[str]:
    """Render compact endpoint findings while retaining scan outcomes."""
    native_count = len(summary.open_ports) if native_open_port_count is None else native_open_port_count
    hidden_count = max(0, native_count - len(summary.open_ports))
    addresses = scan_addresses(summary)
    expected = 0 if getattr(summary, "status", None) == "unconfirmed" else summary.scanned_ports * len(addresses)
    completed = getattr(summary, "completed_attempts", 0)
    status = getattr(summary, "status", "unknown")
    outcomes = getattr(summary, "outcomes", {})
    family_groups = {
        "ipv4": [
            a.address for a in getattr(summary, "addresses", ())
            if a.family_name == "ipv4"
        ],
        "ipv6": [
            a.address for a in getattr(summary, "addresses", ())
            if a.family_name == "ipv6"
        ],
    }
    resolved_label = "; ".join(
        f"{family.upper()}: {', '.join(values)}"
        for family, values in family_groups.items() if values
    ) or ", ".join(addresses)
    report_title = (
        f"Hylianscan scan report for {escape_controls(summary.target_host)} "
        f"({escape_controls(resolved_label)})"
    )
    lines = [] if quiet else [format_separator(), "[ SCAN BY THE TRIFORCE " + get_triforce_symbol() + " ]"]
    lines.append(report_title)
    lines.extend([
        f"Scope: {escape_controls(scan_scope)} ({summary.scanned_ports:,} "
        f"{'port' if summary.scanned_ports == 1 else 'ports'}/address)",
        f"Attempts: {completed:,}/{expected:,} finished" + (
            " (interrupted)" if status == "interrupted" else
            " (host discovery unconfirmed)" if status == "unconfirmed" else ""
        ),
    ])
    results = [f"{native_count:,} open"]
    for key, label in (
        ("refused", "refused"),
        ("timeout", "unknown (connection timeout)"),
        ("unreachable", "unknown (unreachable)"),
        ("error", "unknown (connection error)"),
    ):
        if outcomes.get(key):
            results.append(f"{outcomes[key]:,} {label}")
    lines.append(f"Results: {'; '.join(results)}")
    total_duration = getattr(summary, "phase_durations", {}).get("total")
    timing = f"Time: native {summary.duration:.2f}s"
    if total_duration is not None:
        timing += f"; overall {total_duration:.2f}s"
    lines.append(timing)
    if completed < expected:
        remaining = expected - completed
        lines.append(f"Missing outcomes: {remaining:,} {'attempt' if remaining == 1 else 'attempts'}")
    if http_status_filter is not None:
        lines.append(f"HTTP filter: {escape_controls(http_status_filter)} (report only); "
                     f"{len(summary.open_ports)} shown, {hidden_count} hidden")
    if not quiet:
        lines.append(format_separator())

    if not summary.open_ports:
        lines.extend(["", "No open findings matched the HTTP filter." if hidden_count else
                      "TCP scan skipped: host discovery unconfirmed." if status == "unconfirmed"
                      else "No open ports observed."])
        if not quiet:
            lines.append(format_separator())
        return lines

    findings: list[tuple[str, int]] = []
    for finding in summary.open_ports:
        # Never attribute a legacy finding to an arbitrary IP in a multi-address run.
        address = format_finding_address(finding) or (
            addresses[0] if len(addresses) == 1 else "?"
        )
        findings.append((address, finding.port))
    lines.append("")
    for address, port in sorted(findings):
        endpoint = f"[{address}]" if ":" in address else address
        lines.append(f"Open {endpoint}:{port}")
    if len(addresses) > 1 and all(address != "?" for address, _ in findings):
        shown_addresses = {address for address, _ in findings}
        without_findings = [address for address in addresses if address not in shown_addresses]
        for address in without_findings:
            if http_status_filter is None:
                lines.append(f"{address}: no open TCP ports observed")
            else:
                lines.append(f"{address}: no findings match the HTTP filter")
    if not quiet:
        lines.append(format_separator())
    return lines


def build_final_panel(
    summary: ScanResult,
    scan_scope: str = "Default Target List",
    native_open_port_count: int | None = None,
    http_status_filter: str | None = None,
) -> str:
    lines = build_report_lines(summary, scan_scope, native_open_port_count, http_status_filter)
    report = wrap_report("\n".join(lines))
    colored = []
    for line in report.splitlines():
        if line == "[ SCAN BY THE TRIFORCE " + get_triforce_symbol() + " ]":
            colored.append(format_panel_title())
        elif line == format_separator():
            colored.append(f"{MUTED_GRAY}{line}{RESET}")
        elif line.startswith("Open "):
            colored.append(f"{GREEN}{line}{RESET}")
        elif line.startswith(("Hylianscan scan report", "Scope:", "Attempts:", "Results:", "Time:")):
            colored.append(f"{BRIGHT_WHITE}{line}{RESET}")
        elif line.startswith(("No open findings", "TCP scan skipped", "No open ports observed")):
            colored.append(f"{WARNING_YELLOW}{line}{RESET}")
        else:
            colored.append(line)
    return "\n" + "\n".join(colored)


def build_nmap_panel(report: str, *, quiet: bool = False) -> str:
    """Decorate the Nmap summary while retaining plain quiet output."""
    if quiet:
        return report
    report = wrap_report(report.replace("Nmap service scan", "[+] NMAP SERVICE SCAN", 1))
    return f"{GREEN}{report}{RESET}\n{MUTED_GRAY}{format_separator()}{RESET}"


def build_saved_text_report(
    summary: ScanResult,
    scan_scope: str = "Default Target List",
    base_report: str | None = None,
    match_code_expression: str | None = None,
    nmap_text: str | None = None,
) -> str:
    """Keep TXT readable; detailed settings, bytes, and TLS remain in JSON."""
    report = base_report or build_quiet_final_panel(
        summary, scan_scope=scan_scope, http_status_filter=match_code_expression,
    )
    metadata = []
    for label, field in (("Run ID", "run_id"), ("Started", "started_at"), ("Finished", "finished_at")):
        value = getattr(summary, field, None)
        if value:
            metadata.append(f"{label}: {escape_controls(value)}")
    if nmap_text:
        report += "\n\n" + nmap_text
    return report + ("\n\n" + wrap_report("\n".join(metadata)) if metadata else "")


def build_quiet_final_panel(
    summary: ScanResult,
    scan_scope: str = "Default Target List",
    native_open_port_count: int | None = None,
    http_status_filter: str | None = None,
) -> str:
    """Render the findings without decorative branding or terminal controls."""
    return wrap_report("\n".join(build_report_lines(
        summary, scan_scope, native_open_port_count, http_status_filter, quiet=True,
    )))
