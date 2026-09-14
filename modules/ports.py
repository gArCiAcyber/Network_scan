"""TCP port metadata and selection helpers for hylianscan."""

import ipaddress
from collections.abc import Iterable

from modules.probes.registry import HTTP_PORTS, HTTPS_PORTS, PROTOCOL_PROBE_REGISTRY


COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    2052: "HTTP-Alt",
    2053: "HTTPS-Alt",
    2082: "HTTP-Alt",
    2083: "HTTPS-Alt",
    2086: "HTTP-Alt",
    2087: "HTTPS-Alt",
    2095: "HTTP-Alt",
    2096: "HTTPS-Alt",
    3306: "MySQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8880: "HTTP-Alt",
}

SERVICE_NAMES: dict[int, str] = {
    **COMMON_PORTS,
    110: "POP3",
    143: "IMAP",
    636: "LDAPS",
    989: "FTPS-Data",
    993: "IMAPS",
    995: "POP3S",
}

for probe in PROTOCOL_PROBE_REGISTRY:
    if probe.protocol_name != "generic_tls_metadata":
        for port in probe.ports:
            SERVICE_NAMES.setdefault(port, probe.protocol_name.upper())

WEB_PORT_SCHEMES: dict[int, str] = {
    **dict.fromkeys(HTTP_PORTS, "http"),
    **dict.fromkeys(HTTPS_PORTS, "https"),
}

# Snapshot of Nmap's TCP open-frequency ranking (nmap-services, 2025):
# https://svn.nmap.org/nmap/nmap-services
TOP_400_TCP_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
    5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
    2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
    544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
    7070, 5190, 3000, 5432, 3986, 1900, 13, 1029, 9, 5051,
    6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
    1000, 3001, 5001, 82, 10010, 1030, 9090, 2107, 1024, 2103,
    6004, 1801, 5050, 19, 8031, 1041, 255, 1048, 1054, 2967,
    1065, 1053, 3703, 1049, 1056, 1064, 17, 808, 3689, 1031,
    1071, 1044, 5901, 100, 9102, 4001, 2869, 8010, 1039, 9000,
    5120, 2105, 636, 1038, 2601, 7000, 1, 1066, 1069, 625,
    311, 280, 254, 4000, 1761, 5003, 2002, 2005, 1998, 1032,
    1050, 6112, 3690, 1521, 2161, 1080, 6002, 2401, 4045, 902,
    787, 7937, 1058, 2383, 32771, 1059, 1040, 1033, 50000, 5555,
    10001, 1494, 2301, 593, 3, 3268, 7938, 1234, 1022, 1036,
    1037, 1035, 9001, 8002, 1074, 464, 6666, 1935, 2003, 497,
    6543, 24, 1352, 3269, 1111, 500, 407, 20, 2006, 1034,
    15000, 1218, 3260, 4444, 264, 2004, 33, 1042, 42510, 3052,
    999, 1023, 222, 1068, 7100, 888, 563, 1717, 32770, 992,
    2008, 7001, 32772, 2007, 8082, 5550, 512, 1043, 2009, 5801,
    2701, 1700, 50001, 7019, 4662, 2065, 42, 2010, 3333, 9535,
    2602, 161, 5100, 5002, 2604, 4002, 8193, 52869, 6789, 20828,
    1052, 8089, 8701, 33354, 1055, 65000, 6059, 8651, 35500, 9595,
    9594, 8194, 8652, 2702, 1060, 1311, 1047, 23502, 1062, 9415,
    32769, 3283, 5226, 5225, 1051, 8192, 4443, 64680, 9593, 64623,
    16993, 55600, 16992, 55555, 65389, 13782, 1067, 366, 5902, 9050,
    1002, 5500, 85, 10243, 51103, 1863, 45100, 5431, 8085, 1864,
    49999, 49, 6667, 90, 27000, 6881, 1503, 1500, 8021, 340,
    9071, 8088, 8899, 2222, 5566, 6005, 5102, 9101, 1501, 32774,
    32773, 9876, 163, 5679, 648, 146, 1666, 901, 83, 8083,
    8084, 8001, 5214, 3476, 9207, 14238, 5004, 912, 12345, 30,
    2605, 2030, 6, 541, 1248, 4, 8007, 3005, 2500, 306,
    880, 8291, 2525, 1086, 1088, 9009, 1097, 4242, 52822, 6101,
    900, 7200, 2809, 32775, 12000, 800, 211, 987, 1083, 705,
    711, 20005, 6969, 13783, 30718, 2718, 58080, 8873, 1057, 3551,
    60020, 33899, 31038, 1840, 7741, 1272, 5959, 34572, 1148, 2119,
]


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
    return SERVICE_NAMES.get(port, "Unknown")


def build_web_url(resolved_ip: str, port: int) -> str | None:
    """Return a browser-friendly URL hint for common web service ports."""
    scheme = WEB_PORT_SCHEMES.get(port)

    if scheme is None:
        return None

    host = resolved_ip

    try:
        if ipaddress.ip_address(resolved_ip).version == 6:
            host = f"[{resolved_ip}]"
    except ValueError:
        pass

    if port in (80, 443):
        return f"{scheme}://{host}"

    return f"{scheme}://{host}:{port}"
