"""Nmap XML import helpers for optional service enrichment."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import xml.etree.ElementTree as ET


@dataclass(frozen=True)
class NmapRunMetadata:
    """Top-level Nmap run metadata."""

    scanner: str | None
    args: str | None
    start: str | None
    startstr: str | None
    version: str | None
    xmloutputversion: str | None


@dataclass(frozen=True)
class NmapAddress:
    """Normalized host address from Nmap XML."""

    address: str
    address_type: str | None
    vendor: str | None


@dataclass(frozen=True)
class NmapService:
    """Normalized service details for an open Nmap port."""

    name: str | None
    product: str | None
    version: str | None
    extrainfo: str | None
    tunnel: str | None
    method: str | None
    confidence_raw: int | None
    confidence: str
    cpes: tuple[str, ...]


@dataclass(frozen=True)
class NmapPort:
    """Normalized open TCP port imported from Nmap XML."""

    protocol: str
    port: int
    state: str
    service: NmapService


@dataclass(frozen=True)
class NmapHost:
    """Normalized up host imported from Nmap XML."""

    status: str
    addresses: tuple[NmapAddress, ...]
    open_tcp_ports: tuple[NmapPort, ...]

    @property
    def primary_address(self) -> str:
        """Return the best display address for the imported host."""
        for address in self.addresses:
            if address.address_type == "ipv4":
                return address.address

        if self.addresses:
            return self.addresses[0].address

        return "unknown"


@dataclass(frozen=True)
class NmapXmlImport:
    """Normalized Nmap XML import document."""

    metadata: NmapRunMetadata
    up_hosts: tuple[NmapHost, ...]


def normalize_confidence(confidence: str | None) -> str:
    """Normalize Nmap service confidence into a small stable label."""
    try:
        confidence_value = int(confidence) if confidence is not None else None
    except ValueError:
        return "unknown"

    if confidence_value is None:
        return "unknown"

    if 1 <= confidence_value <= 3:
        return "low"

    if 4 <= confidence_value <= 6:
        return "medium"

    if 7 <= confidence_value <= 10:
        return "high"

    return "unknown"


def parse_confidence_raw(confidence: str | None) -> int | None:
    """Return Nmap's raw confidence value when it is valid."""
    try:
        confidence_value = int(confidence) if confidence is not None else None
    except ValueError:
        return None

    if confidence_value is None or not 1 <= confidence_value <= 10:
        return None

    return confidence_value


def parse_nmap_xml_file(xml_path: str | Path) -> NmapXmlImport:
    """Parse an Nmap XML file into a normalized import document."""
    path = Path(xml_path)

    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as error:
        raise ValueError(f"Invalid Nmap XML: malformed XML ({error}).") from error
    except OSError as error:
        raise ValueError(f"Unable to read Nmap XML file: {error}") from error

    return parse_nmap_xml_root(root)


def parse_nmap_xml_text(xml_text: str) -> NmapXmlImport:
    """Parse Nmap XML text into a normalized import document."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        raise ValueError(f"Invalid Nmap XML: malformed XML ({error}).") from error

    return parse_nmap_xml_root(root)


def parse_single_host_nmap_xml_file(xml_path: str | Path) -> NmapXmlImport:
    """Parse an Nmap XML file and require exactly one up host."""
    import_result = parse_nmap_xml_file(xml_path)
    require_single_up_host(import_result)
    return import_result


def require_single_up_host(import_result: NmapXmlImport) -> NmapHost:
    """Return the only up host or raise a clear import-mode error."""
    up_host_count = len(import_result.up_hosts)

    if up_host_count == 1:
        return import_result.up_hosts[0]

    if up_host_count > 1:
        raise ValueError(
            "Nmap XML import currently supports exactly one up host; "
            f"found {up_host_count}. Multi-host import is not supported yet."
        )

    raise ValueError("Nmap XML import requires exactly one up host; found 0.")


def format_nmap_xml_import_summary(
    import_result: NmapXmlImport,
    xml_path: str | Path,
) -> str:
    """Build the plain-text Nmap XML import summary."""
    host = require_single_up_host(import_result)
    lines = [
        "Nmap XML Import",
        f"Imported XML: {xml_path}",
        f"Host: {host.primary_address}",
        f"Open TCP Ports: {len(host.open_tcp_ports)}",
        "",
    ]

    for port in host.open_tcp_ports:
        service = port.service
        lines.append(
            f"{port.port}/tcp".ljust(8)
            + " "
            + f"{service.name or 'unknown':<8}"
            + " "
            + f"{format_service_version(service):<24}"
            + " "
            + f"method={service.method or 'unknown'} "
            + f"confidence={service.confidence}"
        )

    return "\n".join(lines).rstrip()


def format_service_version(service: NmapService) -> str:
    """Return a compact product/version/extrainfo label for display."""
    parts = [
        value
        for value in (service.product, service.version)
        if value is not None and value.strip()
    ]

    if service.extrainfo:
        parts.append(f"({service.extrainfo})")

    return " ".join(parts) if parts else "-"


def parse_nmap_xml_root(root: ET.Element) -> NmapXmlImport:
    """Parse a validated XML root element."""
    if local_name(root.tag) != "nmaprun":
        raise ValueError("Invalid Nmap XML: root element must be <nmaprun>.")

    metadata = NmapRunMetadata(
        scanner=root.attrib.get("scanner"),
        args=root.attrib.get("args"),
        start=root.attrib.get("start"),
        startstr=root.attrib.get("startstr"),
        version=root.attrib.get("version"),
        xmloutputversion=root.attrib.get("xmloutputversion"),
    )
    up_hosts = tuple(
        parse_host(host)
        for host in children(root, "host")
        if host_is_up(host)
    )

    return NmapXmlImport(metadata=metadata, up_hosts=up_hosts)


def parse_host(host: ET.Element) -> NmapHost:
    """Parse one up Nmap host."""
    addresses = tuple(
        NmapAddress(
            address=address.attrib.get("addr", ""),
            address_type=address.attrib.get("addrtype"),
            vendor=address.attrib.get("vendor"),
        )
        for address in children(host, "address")
        if address.attrib.get("addr")
    )
    ports_parent = first_child(host, "ports")
    open_tcp_ports = tuple(parse_open_tcp_ports(ports_parent))

    return NmapHost(
        status="up",
        addresses=addresses,
        open_tcp_ports=open_tcp_ports,
    )


def parse_open_tcp_ports(ports_parent: ET.Element | None) -> list[NmapPort]:
    """Parse open TCP ports from a host ports element."""
    if ports_parent is None:
        return []

    open_ports: list[NmapPort] = []

    for port in children(ports_parent, "port"):
        if port.attrib.get("protocol") != "tcp":
            continue

        state = first_child(port, "state")
        if state is None or state.attrib.get("state") != "open":
            continue

        try:
            port_number = int(port.attrib["portid"])
        except (KeyError, ValueError) as error:
            raise ValueError("Invalid Nmap XML: open TCP port has invalid portid.") from error

        open_ports.append(
            NmapPort(
                protocol="tcp",
                port=port_number,
                state="open",
                service=parse_service(first_child(port, "service")),
            )
        )

    return open_ports


def parse_service(service: ET.Element | None) -> NmapService:
    """Parse service metadata from one Nmap port."""
    if service is None:
        return NmapService(
            name=None,
            product=None,
            version=None,
            extrainfo=None,
            tunnel=None,
            method=None,
            confidence_raw=None,
            confidence="unknown",
            cpes=(),
        )

    confidence = service.attrib.get("conf")

    return NmapService(
        name=service.attrib.get("name"),
        product=service.attrib.get("product"),
        version=service.attrib.get("version"),
        extrainfo=service.attrib.get("extrainfo"),
        tunnel=service.attrib.get("tunnel"),
        method=service.attrib.get("method"),
        confidence_raw=parse_confidence_raw(confidence),
        confidence=normalize_confidence(confidence),
        cpes=tuple(cpe.text.strip() for cpe in children(service, "cpe") if cpe.text),
    )


def host_is_up(host: ET.Element) -> bool:
    """Return True when a host has status state=up."""
    status = first_child(host, "status")
    return status is not None and status.attrib.get("state") == "up"


def first_child(element: ET.Element, name: str) -> ET.Element | None:
    """Return the first direct child with a matching local tag name."""
    for child in element:
        if local_name(child.tag) == name:
            return child

    return None


def children(element: ET.Element, name: str) -> list[ET.Element]:
    """Return direct children with a matching local tag name."""
    return [child for child in element if local_name(child.tag) == name]


def local_name(tag: str) -> str:
    """Return a namespace-free XML tag name."""
    return tag.rsplit("}", maxsplit=1)[-1]
