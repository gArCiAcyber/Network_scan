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
from modules.target import ResolvedAddress, address_family_name, socket_family_for_address


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
    address: str | None = None
    address_family: str | None = None


@dataclass(frozen=True)
class ScanResult:
    """Represents the final threaded TCP scan summary."""

    target_host: str
    resolved_ip: str
    scanned_ports: int
    open_ports: tuple[PortScanResult, ...]
    duration: float
    resolved_ips: tuple[str, ...] = ()
    address_family: str = "ipv4"
    addresses: tuple[ResolvedAddress, ...] = ()

    @property
    def ipv4_open_ports(self) -> tuple[PortScanResult, ...]:
        """Return only open-port findings discovered over IPv4."""
        return tuple(
            finding
            for finding in self.open_ports
            if (finding.address_family or "ipv4") == "ipv4"
        )

    @property
    def ipv6_open_ports(self) -> tuple[PortScanResult, ...]:
        """Return only open-port findings discovered over IPv6."""
        return tuple(
            finding
            for finding in self.open_ports
            if finding.address_family == "ipv6"
        )


def _address_record(
    resolved_ip: str,
    address_family: int | socket.AddressFamily | None,
    scope_id: int = 0,
) -> ResolvedAddress:
    """Normalize legacy IP arguments into a resolved address record."""
    family = (
        socket_family_for_address(resolved_ip)
        if address_family is None
        else socket.AddressFamily(address_family)
    )
    return ResolvedAddress(address=resolved_ip, family=family, scope_id=scope_id)


def discover_open_port(
    target_host: str,
    resolved_ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    pacer: MaxRatePacer | None = None,
    address_family: int | socket.AddressFamily | None = None,
    scope_id: int = 0,
) -> PortScanResult | None:
    """Run TCP connect discovery for one port."""
    try:
        if pacer is not None:
            pacer.wait()

        started_at = time.perf_counter()

        family = (
            socket_family_for_address(resolved_ip)
            if address_family is None
            else socket.AddressFamily(address_family)
        )

        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            connect_code = client.connect_ex(
                _address_record(resolved_ip, family, scope_id).socket_address(port)
            )
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
        address=resolved_ip,
        address_family=address_family_name(family),
    )


def probe_open_service(
    target_host: str,
    resolved_ip: str,
    finding: PortScanResult,
    timeout: float = DEFAULT_TIMEOUT,
    pacer: MaxRatePacer | None = None,
    address_family: int | socket.AddressFamily | None = None,
    scope_id: int = 0,
    http_probing: bool = True,
) -> PortScanResult:
    """Collect service evidence for one discovered open TCP port."""
    if not http_probing and finding.web_url is not None:
        return finding

    banner = None
    tls = None
    probe = None

    try:
        if pacer is not None:
            pacer.wait()

        family = (
            socket_family_for_address(resolved_ip)
            if address_family is None
            else socket.AddressFamily(address_family)
        )

        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            connect_code = client.connect_ex(
                _address_record(resolved_ip, family, scope_id).socket_address(finding.port)
            )

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
        address=finding.address or resolved_ip,
        address_family=finding.address_family or address_family_name(family),
    )


def scan_single_port(
    target_host: str,
    resolved_ip: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    max_rate: float | None = None,
    address_family: int | socket.AddressFamily | None = None,
    http_probing: bool = True,
) -> PortScanResult | None:
    """Scan and probe one TCP port for compatibility with direct callers."""
    pacer = MaxRatePacer(max_rate) if max_rate is not None else None
    finding = discover_open_port(
        target_host,
        resolved_ip,
        port,
        timeout,
        pacer,
        address_family,
    )

    if finding is None:
        return None

    return probe_open_service(
        target_host,
        resolved_ip,
        finding,
        timeout,
        pacer,
        address_family,
        http_probing=http_probing,
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
    max_rate: float | None = None,
    progress_callback: ProgressCallback | None = None,
    open_port_callback: OpenPortCallback | None = None,
    service_probe_start_callback: ServiceProbeStartCallback | None = None,
    service_probe_complete_callback: ServiceProbeCompleteCallback | None = None,
    addresses: Iterable[ResolvedAddress] | None = None,
    http_probing: bool = True,
) -> ScanResult:
    """Run a threaded TCP scan and return a consolidated result."""
    started_at = time.perf_counter()
    ports_to_scan = normalize_ports(ports)
    address_records = tuple(addresses) if addresses is not None else (
        _address_record(resolved_ip, None),
    )

    if not address_records:
        raise ValueError("TCP scan requires at least one resolved address.")

    scan_targets = [
        (address, port)
        for address in address_records
        for port in ports_to_scan
    ]
    worker_count = _build_worker_count(len(scan_targets), max_workers)
    pacer = MaxRatePacer(max_rate) if max_rate is not None else None
    discovered_ports: list[PortScanResult] = []
    open_ports: list[PortScanResult] = []
    completed_count = 0
    executor = ThreadPoolExecutor(max_workers=worker_count)
    cancelled = False

    try:
        future_map: dict[Future[PortScanResult | None], tuple[ResolvedAddress, int]] = {
            executor.submit(
                discover_open_port,
                target_host,
                address.address,
                port,
                timeout,
                pacer,
                address.family,
                address.scope_id,
            ): (address, port)
            for address, port in scan_targets
        }

        for future in as_completed(future_map):
            _address, port = future_map[future]
            completed_count += 1
            result = future.result()

            if result is not None:
                discovered_ports.append(result)

                if open_port_callback is not None:
                    open_port_callback(result)

            if progress_callback is not None:
                progress_callback(completed_count, len(scan_targets), port)

    except KeyboardInterrupt:
        cancelled = True
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        if not cancelled:
            executor.shutdown(wait=True)

    ordered_discovered_ports = tuple(
        sorted(
            discovered_ports,
            key=lambda finding: (
                finding.port,
                finding.address_family or "ipv4",
                finding.address or "",
            ),
        )
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
            future_map: dict[Future[PortScanResult], tuple[ResolvedAddress, int]] = {
                probe_executor.submit(
                    probe_open_service,
                    target_host,
                    finding.address or resolved_ip,
                    finding,
                    timeout,
                    pacer,
                    next(
                        (
                            address.family
                            for address in address_records
                            if address.address == (finding.address or resolved_ip)
                        ),
                        None,
                    ),
                    next(
                        (
                            address.scope_id
                            for address in address_records
                            if address.address == (finding.address or resolved_ip)
                        ),
                        0,
                    ),
                    http_probing,
                ): (
                    next(
                        (
                            address
                            for address in address_records
                            if address.address == (finding.address or resolved_ip)
                        ),
                        address_records[0],
                    ),
                    finding.port,
                )
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

    ordered_open_ports = tuple(
        sorted(
            open_ports,
            key=lambda finding: (
                finding.port,
                finding.address_family or "ipv4",
                finding.address or "",
            ),
        )
    )

    return ScanResult(
        target_host=target_host,
        resolved_ip=resolved_ip,
        scanned_ports=len(ports_to_scan),
        open_ports=ordered_open_ports,
        duration=time.perf_counter() - started_at,
        resolved_ips=tuple(address.address for address in address_records),
        address_family=(
            "dual-stack"
            if {address.family_name for address in address_records}
            == {"ipv4", "ipv6"}
            else address_records[0].family_name
        ),
        addresses=address_records,
    )
