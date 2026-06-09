"""High-performance threaded TCP scanner for hylianscan."""

import socket
import time
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from modules.banner_grabber import (
    grab_banner,
    grab_tls_metadata,
    should_collect_tls_metadata,
)
from modules.ports import build_web_url, get_service_name, normalize_ports


DEFAULT_TIMEOUT = 1.0
DEFAULT_MAX_WORKERS = 16

ProgressCallback = Callable[[int, int, int], None]
OpenPortCallback = Callable[["PortScanResult"], None]


@dataclass(frozen=True)
class PortScanResult:
    """Represents a single open TCP port finding."""

    port: int
    service: str
    banner: str | None
    response_time: float
    web_url: str | None = None
    tls: dict[str, Any] | None = None


@dataclass(frozen=True)
class ScanResult:
    """Represents the final threaded TCP scan summary."""

    target_host: str
    resolved_ip: str
    scanned_ports: int
    open_ports: tuple[PortScanResult, ...]
    duration: float


def scan_single_port(
    target_host: str,
    resolved_ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> PortScanResult | None:
    """Scan one TCP port and return a finding when it is open."""
    started_at = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            connect_code = client.connect_ex((resolved_ip, port))
            response_time = time.perf_counter() - started_at

            if connect_code != 0:
                return None

            if should_collect_tls_metadata(port):
                banner = None
                tls = grab_tls_metadata(client, target_host)
            else:
                banner = grab_banner(client)
                tls = None
    except OSError:
        return None

    service_name = get_service_name(port)
    web_url = build_web_url(resolved_ip, port)

    return PortScanResult(
        port=port,
        service=service_name,
        banner=banner,
        response_time=response_time,
        web_url=web_url,
        tls=tls,
    )


def _build_worker_count(port_count: int, max_workers: int) -> int:
    """Calculate a safe worker count for the current scan."""
    if port_count <= 0:
        return 1

    return max(1, min(max_workers, port_count))


def scan_tcp_ports(
    target_host: str,
    resolved_ip: str,
    ports: Iterable[int] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    progress_callback: ProgressCallback | None = None,
    open_port_callback: OpenPortCallback | None = None,
) -> ScanResult:
    """Run a threaded TCP scan and return a consolidated result."""
    started_at = time.perf_counter()
    ports_to_scan = normalize_ports(ports)
    worker_count = _build_worker_count(len(ports_to_scan), max_workers)
    open_ports: list[PortScanResult] = []
    completed_count = 0
    executor = ThreadPoolExecutor(max_workers=worker_count)
    cancelled = False

    try:
        future_map: dict[Future[PortScanResult | None], int] = {
            executor.submit(scan_single_port, target_host, resolved_ip, port, timeout): port
            for port in ports_to_scan
        }

        for future in as_completed(future_map):
            port = future_map[future]
            completed_count += 1
            result = future.result()

            if result is not None:
                open_ports.append(result)

                if open_port_callback is not None:
                    open_port_callback(result)

            if progress_callback is not None:
                progress_callback(completed_count, len(ports_to_scan), port)

    except KeyboardInterrupt:
        cancelled = True
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        if not cancelled:
            executor.shutdown(wait=True)

    ordered_open_ports = tuple(sorted(open_ports, key=lambda finding: finding.port))

    return ScanResult(
        target_host=target_host,
        resolved_ip=resolved_ip,
        scanned_ports=len(ports_to_scan),
        open_ports=ordered_open_ports,
        duration=time.perf_counter() - started_at,
    )
