"""High-performance threaded TCP scanner for hylianscan."""

import socket
import time
import errno
import math
import threading
import base64
from collections import Counter
from datetime import datetime, timezone
from uuid import uuid4
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from typing import Any

from modules.banner_grabber import grab_service_banner
from modules.probes.generic import PROBE_DEADLINE, PROBE_CANCEL, COLLECTION_ERRORS, COLLECTED_RESPONSES
from modules.target import normalize_host_identity
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
    scope_id: int = 0


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
    run_id: str = ""
    status: str = "completed"
    requested_ports: tuple[int, ...] = ()
    completed_attempts: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)
    errors: dict[str, int] = field(default_factory=dict)
    started_at: str | None = None
    finished_at: str | None = None
    settings: dict[str, Any] = field(default_factory=dict)
    phase_durations: dict[str, float] = field(default_factory=dict)

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
    cancel_event: threading.Event | None = None,
    outcome_callback: Callable[[str, int | None], None] | None = None,
) -> PortScanResult | None:
    """Run TCP connect discovery for one port."""
    try:
        if pacer is not None:
            pacer.wait(cancel_event) if cancel_event is not None else pacer.wait()

        if cancel_event is not None and cancel_event.is_set():
            return None

        started_at = time.perf_counter()

        family = (
            socket_family_for_address(resolved_ip)
            if address_family is None
            else socket.AddressFamily(address_family)
        )

        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            if cancel_event is not None and cancel_event.is_set():
                return None
            connect_code = client.connect_ex(
                _address_record(resolved_ip, family, scope_id).socket_address(port)
            )
            response_time = time.perf_counter() - started_at

            if outcome_callback is not None:
                outcome_callback(connection_outcome(connect_code), connect_code or None)
            if connect_code != 0:
                return None
    except OSError as error:
        if outcome_callback is not None:
            outcome_callback(
                "timeout" if isinstance(error, TimeoutError) else connection_outcome(error.errno or None),
                error.errno,
            )
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
        scope_id=scope_id,
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
    cancel_event: threading.Event | None = None,
    probe_timeout: float | None = None,
) -> PortScanResult:
    """Collect service evidence for one discovered open TCP port."""
    if not http_probing and finding.web_url is not None:
        return replace(finding, probe={"status": "disabled", "method": None})

    banner = None
    tls = None
    probe = None

    try:
        if pacer is not None:
            pacer.wait(cancel_event) if cancel_event is not None else pacer.wait()

        if cancel_event is not None and cancel_event.is_set():
            return replace(finding, probe={"status": "cancelled", "method": None})

        family = (
            socket_family_for_address(resolved_ip)
            if address_family is None
            else socket.AddressFamily(address_family)
        )

        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            if cancel_event is not None and cancel_event.is_set():
                return replace(finding, probe={"status": "cancelled", "method": None})
            connect_code = client.connect_ex(
                _address_record(resolved_ip, family, scope_id).socket_address(finding.port)
            )

            if connect_code != 0:
                return replace(finding, probe={"status": "failed", "method": None,
                                               "error": f"connect_ex: {connect_code}"})

            errors = []
            responses = []
            deadline_token = PROBE_DEADLINE.set(time.monotonic() + (probe_timeout if probe_timeout is not None else 10.0))
            cancel_token = PROBE_CANCEL.set(cancel_event)
            errors_token = COLLECTION_ERRORS.set(errors)
            responses_token = COLLECTED_RESPONSES.set(responses)
            try:
                banner, tls, probe = grab_service_banner(client, normalize_host_identity(target_host), finding.port)
            finally:
                PROBE_DEADLINE.reset(deadline_token)
                PROBE_CANCEL.reset(cancel_token)
                COLLECTION_ERRORS.reset(errors_token)
                COLLECTED_RESPONSES.reset(responses_token)
            probe = {**(probe or {}), "responses_base64": [
                base64.b64encode(data).decode("ascii") for data in responses]}
            if errors:
                probe = {**(probe or {}), "error": "; ".join(errors)}
    except (OSError, ValueError) as error:
        return replace(finding, probe={"status": "failed", "method": None, "error": str(error)})

    if tls and tls.get("status") == "failed":
        probe = {**(probe or {}), "error": tls.get("error")}
    probe = {**(probe or {}), "status": (
        "incomplete" if probe and probe.get("error") and banner else
        "failed" if probe and probe.get("error") else
        "completed" if banner or tls else "unavailable")}

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
        scope_id=finding.scope_id or scope_id,
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


def connection_outcome(code: int | None) -> str:
    """Classify connection observations without inferring remote port states."""
    if code == 0:
        return "open"
    if code in (errno.ECONNREFUSED, 10061):
        return "refused"
    if code in (errno.ETIMEDOUT, errno.EWOULDBLOCK, 10060, 10035):
        return "timeout"
    if code in (errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065):
        return "unreachable"
    return "error"


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
    pacer: MaxRatePacer | None = None,
    probe_timeout: float | None = None,
) -> ScanResult:
    """Discover then probe; cancellation returns all evidence collected so far."""
    started_at = time.perf_counter()
    started_utc = datetime.now(timezone.utc).isoformat()
    ports_to_scan = normalize_ports(ports)
    address_records = tuple(addresses) if addresses is not None else (_address_record(resolved_ip, None),)
    if not address_records or not ports_to_scan:
        raise ValueError("TCP scan requires addresses and at least one port.")
    if max_workers <= 0 or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Workers and finite timeout must be positive.")
    if probe_timeout is not None and (not math.isfinite(probe_timeout) or probe_timeout <= 0):
        raise ValueError("Probe timeout must be finite and positive.")
    pacer = pacer if pacer is not None else (MaxRatePacer(max_rate) if max_rate is not None else None)
    cancelled = threading.Event()
    outcomes = Counter()
    errors = Counter()
    outcome_lock = threading.Lock()
    findings = {}
    completed_count = 0
    phase_durations = {}

    def record_outcome(state, code):
        with outcome_lock:
            outcomes[state] += 1
            if state in {"error", "unreachable"}:
                errors[str(code) if code is not None else "unknown"] += 1

    for phase in ("discovery", "probing"):
        if cancelled.is_set():
            break
        work = ([(address, port) for address in address_records for port in ports_to_scan]
                if phase == "discovery" else list(findings.items()))
        if not work:
            continue
        phase_started = time.perf_counter()
        executor = ThreadPoolExecutor(max_workers=_build_worker_count(len(work), max_workers))
        futures = {}
        consumed = set()

        def collect(future, callbacks=True):
            nonlocal completed_count
            if future in consumed or future.cancelled():
                return
            consumed.add(future)
            result = future.result()
            if phase == "discovery":
                address, port = futures[future]
                completed_count += 1
                if result is not None:
                    result = replace(result, address=address.address,
                                     address_family=address.family_name, scope_id=address.scope_id)
                    findings[(address, port)] = result
                    if callbacks and open_port_callback is not None:
                        open_port_callback(result)
                if callbacks and progress_callback is not None:
                    progress_callback(completed_count, len(work), port)
            elif result is not None:
                findings[futures[future]] = result

        try:
            if phase == "probing" and service_probe_start_callback is not None:
                service_probe_start_callback(len(work))
            for item in work:
                if phase == "discovery":
                    address, port = item
                    future = executor.submit(discover_open_port, target_host, address.address,
                        port, timeout, pacer, address.family, address.scope_id,
                        cancel_event=cancelled, outcome_callback=record_outcome)
                    futures[future] = item
                else:
                    key, finding = item
                    address, _ = key
                    future = executor.submit(probe_open_service, target_host, address.address,
                        finding, timeout, pacer, address.family, address.scope_id, http_probing,
                        cancel_event=cancelled, probe_timeout=probe_timeout)
                    futures[future] = key
            for future in as_completed(futures):
                collect(future)
        except KeyboardInterrupt:
            cancelled.set()
        finally:
            executor.shutdown(wait=True, cancel_futures=cancelled.is_set())
            # Finished workers may hold evidence the interrupted iterator never delivered.
            for future in futures:
                collect(future, callbacks=False)
            phase_durations[phase] = time.perf_counter() - phase_started
        if phase == "probing" and not cancelled.is_set() and service_probe_complete_callback is not None:
            try:
                service_probe_complete_callback(phase_durations[phase])
            except KeyboardInterrupt:
                cancelled.set()

    return ScanResult(
        target_host=target_host, resolved_ip=resolved_ip, scanned_ports=len(ports_to_scan),
        open_ports=tuple(sorted(findings.values(), key=lambda f: (f.port, f.address or "", f.scope_id))),
        duration=time.perf_counter() - started_at,
        resolved_ips=tuple(a.address for a in address_records),
        address_family="dual-stack" if len({a.family for a in address_records}) > 1 else address_records[0].family_name,
        addresses=address_records, run_id=uuid4().hex,
        status="interrupted" if cancelled.is_set() else ("partial" if errors or outcomes["timeout"] else "completed"),
        requested_ports=ports_to_scan, completed_attempts=sum(outcomes.values()),
        outcomes=dict(outcomes), errors=dict(errors), started_at=started_utc,
        finished_at=datetime.now(timezone.utc).isoformat(),
        settings={"timeout": timeout, "workers": max_workers, "max_rate": max_rate,
                  "http_probing": http_probing, "probe_timeout": probe_timeout if probe_timeout is not None else 10.0},
        phase_durations=phase_durations,
    )
