"""High-performance threaded TCP scanner for hylianscan."""

import socket
import time
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass


DEFAULT_TIMEOUT = 1.0
DEFAULT_MAX_WORKERS = 16
BANNER_SIZE = 1024

COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    8080: "HTTP-Alt",
}

ProgressCallback = Callable[[int, int, int], None]
OpenPortCallback = Callable[["PortScanResult"], None]


@dataclass(frozen=True)
class PortScanResult:
    """Represents a single open TCP port finding."""

    port: int
    service: str
    banner: str | None
    response_time: float


@dataclass(frozen=True)
class ScanResult:
    """Represents the final threaded TCP scan summary."""

    target_host: str
    resolved_ip: str
    scanned_ports: int
    open_ports: tuple[PortScanResult, ...]
    duration: float


def get_default_ports() -> tuple[int, ...]:
    """Return the default TCP ports scanned by hylianscan."""
    return tuple(COMMON_PORTS.keys())


def normalize_ports(ports: Iterable[int] | None = None) -> tuple[int, ...]:
    """Normalize, deduplicate, and sort the requested port list."""
    base_ports = ports if ports is not None else get_default_ports()
    normalized_ports = {int(port) for port in base_ports}
    return tuple(sorted(normalized_ports))


def get_service_name(port: int) -> str:
    """Return the expected service name for a common TCP port."""
    return COMMON_PORTS.get(port, "Unknown")


def clean_banner(data: bytes) -> str:
    """Decode received service bytes into a compact text banner."""
    text = data.decode("utf-8", errors="replace")
    return " ".join(text.split())


def grab_banner(client: socket.socket) -> str | None:
    """Attempt passive banner grabbing on an open TCP socket."""
    try:
        data = client.recv(BANNER_SIZE)
    except socket.timeout:
        return None
    except OSError:
        return None

    banner = clean_banner(data)
    return banner or None


def scan_single_port(
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

            banner = grab_banner(client)
    except OSError:
        return None

# 1. Pega o nome padrão do serviço (HTTP, HTTPS, etc.)
    service_name = get_service_name(port)

    # 2. Injeta a lógica de link clicável para portas web
    if port == 80:
        service_name = f"{service_name} | http://{resolved_ip}"
    elif port == 443:
        service_name = f"{service_name} | https://{resolved_ip}"
    elif port in (8080, 8000, 8443):
        service_name = f"{service_name} | http://{resolved_ip}:{port}"

    # 3. Retorna o resultado com o link 
    return PortScanResult(
        port=port,
        service=service_name,
        banner=banner,
        response_time=response_time,
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
            executor.submit(scan_single_port, resolved_ip, port, timeout): port
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

