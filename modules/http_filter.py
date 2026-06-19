"""Post-probe HTTP finding filters for hylianscan reports."""

from dataclasses import replace

from modules.json_exporter import parse_http_metadata
from modules.tcp_scanner import ScanResult


def filter_scan_result_by_http_status(
    scan_result: ScanResult,
    match_codes: list[int] | None,
) -> ScanResult:
    """Return report findings matching configured HTTP response codes."""
    if match_codes is None:
        return scan_result

    accepted_codes = set(match_codes)
    matching_findings = tuple(
        finding
        for finding in scan_result.open_ports
        if parse_http_metadata(finding.banner, finding.web_url).get("status_code")
        in accepted_codes
    )
    return replace(scan_result, open_ports=matching_findings)
