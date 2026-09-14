"""Optional ICMP and TCP host discovery helpers."""

from __future__ import annotations

import errno
import math
import os
import socket
import subprocess
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from modules.target import ResolvedAddress


DEFAULT_DISCOVERY_TIMEOUT = 1.0
DEFAULT_TCP_DISCOVERY_PORTS = (443, 80, 22)


@dataclass(frozen=True)
class HostDiscoveryResult:
    """Result of one ICMP or TCP host-discovery probe."""

    address: ResolvedAddress
    method: str
    is_up: bool
    response_time: float
    error: str | None = None


def _discover_tcp(
    address: ResolvedAddress,
    timeout: float,
    ports: Sequence[int],
) -> HostDiscoveryResult:
    """Treat an accepted or refused TCP connection as a reachable host."""
    started_at = time.perf_counter()

    for port in ports:
        try:
            with socket.socket(address.family, socket.SOCK_STREAM) as client:
                client.settimeout(timeout)
                result = client.connect_ex(address.socket_address(port))
        except OSError:
            continue

        if result in (0, errno.ECONNREFUSED, 10061):
            return HostDiscoveryResult(
                address=address,
                method="tcp",
                is_up=True,
                response_time=time.perf_counter() - started_at,
            )

    return HostDiscoveryResult(
        address=address,
        method="tcp",
        is_up=False,
        response_time=time.perf_counter() - started_at,
        error="No TCP discovery port responded.",
    )


def _ping_target(address: ResolvedAddress) -> str:
    """Return a ping-safe address, including an IPv6 scope when available."""
    if address.family == socket.AF_INET6 and address.scope_id and "%" not in address.address:
        return f"{address.address}%{address.scope_id}"

    return address.address


def _build_ping_command(address: ResolvedAddress, timeout: float) -> list[str]:
    """Build a shell-free platform-specific one-packet ping command."""
    target = _ping_target(address)

    if os.name == "nt":
        command = ["ping"]
        if address.family == socket.AF_INET6:
            command.append("-6")
        return command + ["-n", "1", "-w", str(max(1, math.ceil(timeout * 1000))), target]

    command = ["ping"]
    if address.family == socket.AF_INET6:
        command.append("-6")
    return command + ["-c", "1", "-W", str(max(1, math.ceil(timeout))), target]


def _discover_icmp(
    address: ResolvedAddress,
    timeout: float,
) -> HostDiscoveryResult:
    """Use the operating system ping utility for optional ICMP discovery."""
    started_at = time.perf_counter()

    try:
        completed = subprocess.run(
            _build_ping_command(address, timeout),
            shell=False,
            capture_output=True,
            timeout=timeout + 1.0,
            check=False,
        )
    except FileNotFoundError:
        return HostDiscoveryResult(
            address=address,
            method="icmp",
            is_up=False,
            response_time=time.perf_counter() - started_at,
            error="The ping executable was not found.",
        )
    except subprocess.TimeoutExpired:
        return HostDiscoveryResult(
            address=address,
            method="icmp",
            is_up=False,
            response_time=time.perf_counter() - started_at,
            error="ICMP discovery timed out.",
        )
    except OSError as error:
        return HostDiscoveryResult(
            address=address,
            method="icmp",
            is_up=False,
            response_time=time.perf_counter() - started_at,
            error=str(error),
        )

    return HostDiscoveryResult(
        address=address,
        method="icmp",
        is_up=completed.returncode == 0,
        response_time=time.perf_counter() - started_at,
        error=None if completed.returncode == 0 else f"ping exited with code {completed.returncode}.",
    )


def discover_host(
    address: ResolvedAddress,
    method: str,
    timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
    tcp_ports: Sequence[int] = DEFAULT_TCP_DISCOVERY_PORTS,
) -> HostDiscoveryResult:
    """Discover one resolved address with TCP or ICMP."""
    if timeout <= 0:
        raise ValueError("Host discovery timeout must be greater than zero.")

    normalized_method = method.strip().lower()

    if normalized_method == "tcp":
        return _discover_tcp(address, timeout, tcp_ports)

    if normalized_method == "icmp":
        return _discover_icmp(address, timeout)

    raise ValueError("Host discovery method must be tcp or icmp.")


def discover_hosts(
    addresses: Iterable[ResolvedAddress],
    method: str,
    timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
    tcp_ports: Sequence[int] = DEFAULT_TCP_DISCOVERY_PORTS,
) -> tuple[HostDiscoveryResult, ...]:
    """Discover every selected address and preserve IPv4/IPv6 separation."""
    return tuple(
        discover_host(address, method, timeout=timeout, tcp_ports=tcp_ports)
        for address in addresses
    )
