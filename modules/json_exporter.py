"""JSON export helpers for hylianscan TCP scan results."""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol


class PortFindingExportView(Protocol):
    """Minimum fields required to export an open TCP port."""

    port: int
    service: str
    banner: str | None
    response_time: float
    web_url: str | None
    tls: dict[str, Any] | None


class ScanResultExportView(Protocol):
    """Minimum fields required to export a TCP scan summary."""

    target_host: str
    resolved_ip: str
    scanned_ports: int
    open_ports: Sequence[PortFindingExportView]
    duration: float


def build_port_document(finding: PortFindingExportView) -> dict[str, Any]:
    """Build one JSON-ready open-port document."""
    tls_metadata = finding.tls or {
        "status": "not_collected",
        "handshake": {},
        "certificate": {},
        "error": None,
    }

    return {
        "port": finding.port,
        "transport": "tcp",
        "status": "open",
        "service": {
            "name": finding.service,
        },
        "banner": {
            "raw": finding.banner,
        },
        "http": {
            "url": finding.web_url,
        },
        "tls": tls_metadata,
        "timing": {
            "response_time_seconds": round(finding.response_time, 6),
        },
    }


def build_tcp_scan_document(scan_result: ScanResultExportView) -> dict[str, Any]:
    """Build a future-ready JSON document for TCP scan results."""
    return {
        "schema": {
            "name": "hylianscan_tcp_scan",
            "version": 1,
        },
        "scan": {
            "type": "tcp",
            "target": {
                "host": scan_result.target_host,
                "resolved_ip": scan_result.resolved_ip,
            },
            "scope": {
                "ports_tested": scan_result.scanned_ports,
            },
            "summary": {
                "open_ports": len(scan_result.open_ports),
            },
            "timing": {
                "duration_seconds": round(scan_result.duration, 6),
            },
        },
        "results": {
            "open_ports": [
                build_port_document(finding)
                for finding in scan_result.open_ports
            ],
        },
    }


def write_tcp_json_report(scan_result: ScanResultExportView, output_path: Path) -> None:
    """Write TCP scan results as pretty JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    document = build_tcp_scan_document(scan_result)
    output_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
