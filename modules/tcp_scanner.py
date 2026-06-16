"""High-performance threaded TCP scanner for hylianscan."""

import socket
import time
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from modules.banner_grabber import grab_service_banner
from modules.ports import build_web_url, get_service_name, normalize_ports
from modules.rate_limiter import MaxRatePacer


DEFAULT_TIMEOUT = 1.0
DEFAULT_MAX_WORKERS = 16

ProgressCallback = Callable[[int, int, int], None]
OpenPortCallback = Callable[["PortScanResult"], None]
ServiceProbeStartCallback = Callable[[int], None]
ServiceProbeCompleteCallback = Callable[[float], None]


@dataclass(frozen=True)
class PortScanResult:
    """Represents a single open TCP port finding."""

    port: int
    service: str
    banner: str | None
    response_time: float
    web_url: str | None = None
    tls: dict[str, Any] | None = None
    probe: dict[str, Any] | None = None


@dataclass(frozen=True)
class ScanResult:
    """Represents the final threaded TCP scan summary."""

    target_host: str
    resolved_ip: str
    scanned_ports: int
    open_ports: tuple[PortScanResult, ...]
    duration: float


def discover_open_port(
    target_host: str,
    resolved_ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    pacer: MaxRatePacer | None = None,
) -> PortScanResult | None:
    """Run TCP connect discovery for one port."""
    try:
        if pacer is not None:
            pacer.wait()

        started_at = time.perf_counter()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            connect_code = client.connect_ex((resolved_ip, port))
            response_time = time.perf_counter() - started_at

            if connect_code != 0:
                return None
    except OSError:
        return None

    service_name = get_service_name(port)
    web_url = build_web_url(resolved_ip, port)

    return PortScanResult(
        port=port,
        service=service_name,
        banner=None,
        response_time=response_time,
        web_url=web_url,
        tls=None,
        probe=None,
    )


def probe_open_service(
    target_host: str,
    resolved_ip: str,
    finding: PortScanResult,
    timeout: float = DEFAULT_TIMEOUT,
    pacer: MaxRatePacer | None = None,
) -> PortScanResult:
    """Collect service evidence for one discovered open TCP port."""
    banner = None
    tls = None
    probe = None

    try:
        if pacer is not None:
            pacer.wait()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            connect_code = client.connect_ex((resolved_ip, finding.port))

            if connect_code != 0:
                return finding

            banner, tls, probe = grab_service_banner(client, target_host, finding.port)
    except OSError:
        return finding

    return PortScanResult(
        port=finding.port,
        service=finding.service,
        banner=banner,
        response_time=finding.response_time,
        web_url=finding.web_url,
        tls=tls,
        probe=probe,
    )


def scan_single_port(
    target_host: str,
    resolved_ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    max_rate: float | None = None,
) -> PortScanResult | None:
    """Scan and probe one TCP port for compatibility with direct callers."""
    pacer = MaxRatePacer(max_rate) if max_rate is not None else None
    finding = discover_open_port(target_host, resolved_ip, port, timeout, pacer)

    if finding is None:
        return None

    return probe_open_service(target_host, resolved_ip, finding, timeout, pacer)


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
    max_rate: float | None = None,
    progress_callback: ProgressCallback | None = None,
    open_port_callback: OpenPortCallback | None = None,
    service_probe_start_callback: ServiceProbeStartCallback | None = None,
    service_probe_complete_callback: ServiceProbeCompleteCallback | None = None,
) -> ScanResult:
    """Run a threaded TCP scan and return a consolidated result."""
    started_at = time.perf_counter()
    ports_to_scan = normalize_ports(ports)
    worker_count = _build_worker_count(len(ports_to_scan), max_workers)
    pacer = MaxRatePacer(max_rate) if max_rate is not None else None
    discovered_ports: list[PortScanResult] = []
    open_ports: list[PortScanResult] = []
    completed_count = 0
    executor = ThreadPoolExecutor(max_workers=worker_count)
    cancelled = False

    try:
        future_map: dict[Future[PortScanResult | None], int] = {
            executor.submit(
                discover_open_port,
                target_host,
                resolved_ip,
                port,
                timeout,
                pacer,
            ): port
            for port in ports_to_scan
        }

        for future in as_completed(future_map):
            port = future_map[future]
            completed_count += 1
            result = future.result()

            if result is not None:
                discovered_ports.append(result)

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

    ordered_discovered_ports = tuple(
        sorted(discovered_ports, key=lambda finding: finding.port)
    )
    probe_started_at = time.perf_counter()

    if service_probe_start_callback is not None:
        service_probe_start_callback(len(ordered_discovered_ports))

    if ordered_discovered_ports:
        probe_worker_count = _build_worker_count(
            len(ordered_discovered_ports),
            max_workers,
        )
        probe_executor = ThreadPoolExecutor(max_workers=probe_worker_count)
        probe_cancelled = False

        try:
            future_map: dict[Future[PortScanResult], int] = {
                probe_executor.submit(
                    probe_open_service,
                    target_host,
                    resolved_ip,
                    finding,
                    timeout,
                    pacer,
                ): finding.port
                for finding in ordered_discovered_ports
            }

            for future in as_completed(future_map):
                open_ports.append(future.result())
        except KeyboardInterrupt:
            probe_cancelled = True
            probe_executor.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            if not probe_cancelled:
                probe_executor.shutdown(wait=True)

    if service_probe_complete_callback is not None:
        service_probe_complete_callback(time.perf_counter() - probe_started_at)

    ordered_open_ports = tuple(sorted(open_ports, key=lambda finding: finding.port))

    return ScanResult(
        target_host=target_host,
        resolved_ip=resolved_ip,
        scanned_ports=len(ports_to_scan),
        open_ports=ordered_open_ports,
        duration=time.perf_counter() - started_at,
    )
