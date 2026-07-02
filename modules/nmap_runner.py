"""Optional live Nmap runner foundation for future service enrichment."""

from __future__ import annotations

from collections.abc import Sequence
import subprocess

from modules.nmap_xml import NmapXmlImport, parse_nmap_xml_text


DEFAULT_NMAP_BINARY = "nmap"
DEFAULT_NMAP_TIMEOUT = 60.0
MAX_PORT = 65535
STDERR_PREVIEW_LIMIT = 500


def normalize_nmap_ports(ports: Sequence[int]) -> list[int]:
    """Validate, deduplicate, and sort TCP ports for an Nmap run."""
    if not ports:
        raise ValueError("Nmap enrichment requires at least one TCP port.")

    normalized_ports: set[int] = set()

    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError(f"Invalid TCP port for Nmap enrichment: {port!r}.")

        if not 1 <= port <= MAX_PORT:
            raise ValueError(f"Invalid TCP port for Nmap enrichment: {port}.")

        normalized_ports.add(port)

    return sorted(normalized_ports)


def build_nmap_service_version_command(
    target: str,
    ports: Sequence[int],
    nmap_binary: str = DEFAULT_NMAP_BINARY,
) -> list[str]:
    """Build a safe Nmap service/version XML command."""
    normalized_ports = normalize_nmap_ports(ports)
    clean_target = target.strip()
    clean_nmap_binary = nmap_binary.strip()

    if not clean_target:
        raise ValueError("Nmap enrichment requires a target host.")

    if not clean_nmap_binary:
        raise ValueError("Nmap enrichment requires an Nmap binary name or path.")

    return [
        clean_nmap_binary,
        "-sT",
        "-sV",
        "-Pn",
        "-n",
        "-p",
        ",".join(str(port) for port in normalized_ports),
        "-oX",
        "-",
        clean_target,
    ]


def run_nmap_service_version_scan(
    target: str,
    ports: Sequence[int],
    *,
    nmap_binary: str = DEFAULT_NMAP_BINARY,
    timeout: float = DEFAULT_NMAP_TIMEOUT,
) -> NmapXmlImport:
    """Run Nmap service/version detection and parse XML stdout."""
    command = build_nmap_service_version_command(
        target,
        ports,
        nmap_binary=nmap_binary,
    )

    try:
        completed_process = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise RuntimeError(
            f"Nmap binary not found: {command[0]}. Install Nmap or provide a valid path."
        ) from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"Nmap service/version enrichment timed out after {timeout:.1f} seconds."
        ) from error

    if completed_process.returncode != 0:
        stderr = format_stderr_preview(completed_process.stderr)
        raise RuntimeError(
            f"Nmap service/version enrichment failed with exit code "
            f"{completed_process.returncode}: {stderr}"
        )

    return parse_nmap_xml_text(completed_process.stdout)


def format_stderr_preview(stderr: str | None) -> str:
    """Return concise stderr text for operator-facing errors."""
    if not stderr or not stderr.strip():
        return "no stderr output"

    compact_stderr = " ".join(stderr.split())

    if len(compact_stderr) <= STDERR_PREVIEW_LIMIT:
        return compact_stderr

    return f"{compact_stderr[:STDERR_PREVIEW_LIMIT].rstrip()}..."
