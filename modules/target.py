"""Target validation, address-family selection, and DNS resolution."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, replace
from typing import Literal


ADDRESS_FAMILY_IPV4 = "ipv4"
ADDRESS_FAMILY_IPV6 = "ipv6"
ADDRESS_FAMILY_DUAL_STACK = "dual-stack"
AddressFamilyMode = Literal["ipv4", "ipv6", "dual-stack"]


class TargetResolutionError(ValueError):
    """Raised when a target cannot be resolved for the requested family."""


@dataclass(frozen=True)
class ResolvedAddress:
    """One address returned by the system resolver."""

    address: str
    family: socket.AddressFamily
    reverse_dns: str | None = None
    scope_id: int = 0

    @property
    def family_name(self) -> str:
        """Return the stable report label for this address family."""
        return address_family_name(self.family)

    def socket_address(self, port: int) -> tuple[str, int] | tuple[str, int, int, int]:
        """Build the socket destination tuple for this address."""
        if self.family == socket.AF_INET6:
            return (self.address, port, 0, self.scope_id)

        return (self.address, port)


@dataclass(frozen=True)
class TargetInfo:
    """Normalized target information used by the scanner."""

    raw_input: str
    target_host: str
    resolved_ip: str
    is_ip_address: bool
    addresses: tuple[ResolvedAddress, ...] = ()
    address_family: AddressFamilyMode = ADDRESS_FAMILY_IPV4

    @property
    def address_records(self) -> tuple[ResolvedAddress, ...]:
        """Return resolved addresses, with a legacy single-IP fallback."""
        if self.addresses:
            return self.addresses

        return (
            ResolvedAddress(
                address=self.resolved_ip,
                family=socket_family_for_address(self.resolved_ip),
            ),
        )

    @property
    def ipv4_addresses(self) -> tuple[ResolvedAddress, ...]:
        """Return only resolved IPv4 addresses."""
        return tuple(
            address
            for address in self.address_records
            if address.family == socket.AF_INET
        )

    @property
    def ipv6_addresses(self) -> tuple[ResolvedAddress, ...]:
        """Return only resolved IPv6 addresses."""
        return tuple(
            address
            for address in self.address_records
            if address.family == socket.AF_INET6
        )

    @property
    def reverse_dns(self) -> dict[str, str | None]:
        """Return PTR results keyed by resolved address."""
        return {
            address.address: address.reverse_dns
            for address in self.address_records
        }

    def with_addresses(self, addresses: tuple[ResolvedAddress, ...]) -> "TargetInfo":
        """Return this target with a filtered address set."""
        if not addresses:
            raise TargetResolutionError("No resolved addresses remain for the target.")

        return replace(
            self,
            addresses=addresses,
            resolved_ip=addresses[0].address,
        )


def normalize_target(value: str) -> str:
    """Trim user input before validation."""
    return value.strip()


def is_ip_address(value: str) -> bool:
    """Return True when the value is a valid IP address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False

    return True


def validate_target(value: str) -> str:
    """Validate that the target is not empty."""
    normalized_value = normalize_target(value)

    if not normalized_value:
        raise TargetResolutionError("No target was provided.")

    return normalized_value


def normalize_address_family(value: str | None) -> AddressFamilyMode:
    """Normalize the public address-family selector."""
    normalized = (value or ADDRESS_FAMILY_DUAL_STACK).strip().lower()
    aliases = {
        "ipv4": ADDRESS_FAMILY_IPV4,
        "4": ADDRESS_FAMILY_IPV4,
        "ipv6": ADDRESS_FAMILY_IPV6,
        "6": ADDRESS_FAMILY_IPV6,
        "dual": ADDRESS_FAMILY_DUAL_STACK,
        "dual-stack": ADDRESS_FAMILY_DUAL_STACK,
        "dual_stack": ADDRESS_FAMILY_DUAL_STACK,
    }

    try:
        return aliases[normalized]  # type: ignore[return-value]
    except KeyError as error:
        raise ValueError(
            "Address family must be ipv4, ipv6, or dual-stack."
        ) from error


def address_family_name(family: int | socket.AddressFamily) -> str:
    """Return the stable report label for a socket family."""
    if family == socket.AF_INET:
        return ADDRESS_FAMILY_IPV4

    if family == socket.AF_INET6:
        return ADDRESS_FAMILY_IPV6

    raise ValueError(f"Unsupported socket address family: {family!r}")


def socket_family_for_address(value: str) -> socket.AddressFamily:
    """Infer a socket family from a numeric IP address."""
    try:
        return (
            socket.AF_INET6
            if ipaddress.ip_address(value).version == 6
            else socket.AF_INET
        )
    except ValueError as error:
        raise TargetResolutionError(f"Invalid resolved IP address: {value}") from error


def _socket_family_for_mode(mode: AddressFamilyMode) -> int:
    if mode == ADDRESS_FAMILY_IPV4:
        return socket.AF_INET

    if mode == ADDRESS_FAMILY_IPV6:
        return socket.AF_INET6

    return socket.AF_UNSPEC


def _reverse_dns(address: str, family: socket.AddressFamily, scope_id: int = 0) -> str | None:
    """Return a PTR hostname when one exists, without making it required."""
    sockaddr = (
        (address, 0, 0, scope_id)
        if family == socket.AF_INET6
        else (address, 0)
    )

    try:
        hostname, _ = socket.getnameinfo(sockaddr, socket.NI_NAMEREQD)
    except OSError:
        return None

    return hostname.rstrip(".") or None


def _resolve_addresses(
    target: str,
    mode: AddressFamilyMode,
) -> tuple[ResolvedAddress, ...]:
    """Resolve and deduplicate addresses for the selected family."""
    try:
        results = socket.getaddrinfo(
            target,
            None,
            _socket_family_for_mode(mode),
            socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        raise TargetResolutionError(f"Could not resolve target: {target}") from error

    addresses: list[ResolvedAddress] = []
    seen: set[tuple[int, str, int]] = set()

    for family, _socktype, _protocol, _canonname, sockaddr in results:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue

        address = sockaddr[0]
        scope_id = sockaddr[3] if family == socket.AF_INET6 and len(sockaddr) > 3 else 0
        key = (family, address, scope_id)

        if key in seen:
            continue

        seen.add(key)
        socket_family = socket.AddressFamily(family)
        addresses.append(
            ResolvedAddress(
                address=address,
                family=socket_family,
                reverse_dns=_reverse_dns(address, socket_family, scope_id),
                scope_id=scope_id,
            )
        )

    if not addresses:
        raise TargetResolutionError(
            f"Target has no {mode} addresses: {target}"
        )

    return tuple(addresses)


def resolve_target(
    value: str,
    address_family: str | None = ADDRESS_FAMILY_DUAL_STACK,
) -> TargetInfo:
    """Resolve a host or IP address with IPv4, IPv6, or dual-stack selection."""
    target = validate_target(value)
    mode = normalize_address_family(address_family)

    numeric_target = None
    try:
        numeric_target = ipaddress.ip_address(target)
    except ValueError:
        pass

    if numeric_target is not None and mode != ADDRESS_FAMILY_DUAL_STACK:
        expected_family = (
            socket.AF_INET
            if mode == ADDRESS_FAMILY_IPV4
            else socket.AF_INET6
        )
        if socket_family_for_address(target) != expected_family:
            raise TargetResolutionError(
                f"Target {target} is not compatible with --{mode}."
            )

    addresses = _resolve_addresses(target, mode)

    if numeric_target is not None:
        requested_family = socket_family_for_address(target)

        if requested_family not in {address.family for address in addresses}:
            raise TargetResolutionError(
                f"Target {target} is not compatible with --{mode}."
            )

    return TargetInfo(
        raw_input=value,
        target_host=target,
        resolved_ip=addresses[0].address,
        is_ip_address=is_ip_address(target),
        addresses=addresses,
        address_family=mode,
    )
