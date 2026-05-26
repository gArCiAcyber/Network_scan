"""Threaded subdomain enumeration engine for hylianscan."""

import queue
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


DEFAULT_THREADS = 10
INVALID_IP = "0.0.0.0"
WILDCARD_PROBE_LABEL = "rnd123hylian"

ProgressCallback = Callable[[int, int, str], None]
FindingCallback = Callable[["SubdomainFinding"], None]


@dataclass(frozen=True)
class SubdomainFinding:
    """Represents one resolved subdomain."""

    hostname: str
    ip_address: str


@dataclass(frozen=True)
class SubdomainResult:
    """Represents the final subdomain enumeration result."""

    base_domain: str
    wordlist_path: str
    tested_count: int
    findings: tuple[SubdomainFinding, ...]
    duration: float


def normalize_base_domain(value: str) -> str:
    """Normalize a base domain for brute-force enumeration."""
    return value.strip().lower().strip(".")


def normalize_word(word: str) -> str | None:
    """Normalize one wordlist entry."""
    candidate = word.strip().lower()

    if not candidate or candidate.startswith("#"):
        return None

    return candidate.strip(".")


def load_wordlist(wordlist_path: str) -> list[str]:
    """Load subdomain candidates from a wordlist file."""
    path = Path(wordlist_path).expanduser()

    if not path.is_file():
        raise ValueError(f"Wordlist not found: {wordlist_path}")

    words: list[str] = []

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            word = normalize_word(line)

            if word is not None:
                words.append(word)

    return sorted(set(words))


def build_hostname(base_domain: str, candidate: str) -> str:
    """Build a fully qualified subdomain candidate."""
    if candidate.endswith(f".{base_domain}"):
        return candidate

    return f"{candidate}.{base_domain}"


def is_invalid_ip(ip_address: str) -> bool:
    """Return True for DNS results that should not be reported."""
    return ip_address == INVALID_IP


def resolve_ip(hostname: str) -> str | None:
    """Resolve a hostname to an IPv4 address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def detect_wildcard_ip(base_domain: str) -> str | None:
    """Detect DNS wildcard behavior before the main enumeration."""
    wildcard_hostname = build_hostname(base_domain, WILDCARD_PROBE_LABEL)
    wildcard_ip = resolve_ip(wildcard_hostname)

    if wildcard_ip is None or is_invalid_ip(wildcard_ip):
        return None

    return wildcard_ip


def resolve_hostname(hostname: str, wildcard_ip: str | None = None) -> SubdomainFinding | None:
    """Resolve a hostname and filter invalid or wildcard DNS results."""
    ip_address = resolve_ip(hostname)

    if ip_address is None:
        return None

    if is_invalid_ip(ip_address):
        return None

    if wildcard_ip is not None and ip_address == wildcard_ip:
        return None

    return SubdomainFinding(hostname=hostname, ip_address=ip_address)


def _worker(
    base_domain: str,
    work_queue: "queue.Queue[str]",
    findings: list[SubdomainFinding],
    findings_lock: threading.Lock,
    progress_state: dict[str, int],
    progress_lock: threading.Lock,
    total_count: int,
    wildcard_ip: str | None,
    progress_callback: ProgressCallback | None,
    finding_callback: FindingCallback | None,
) -> None:
    """Resolve queued subdomain candidates until the queue is empty."""
    while True:
        try:
            candidate = work_queue.get_nowait()
        except queue.Empty:
            return

        hostname = build_hostname(base_domain, candidate)
        finding = resolve_hostname(hostname, wildcard_ip)

        if finding is not None:
            with findings_lock:
                findings.append(finding)

            if finding_callback is not None:
                finding_callback(finding)

        with progress_lock:
            progress_state["completed"] += 1
            completed = progress_state["completed"]

        if progress_callback is not None:
            progress_callback(completed, total_count, hostname)

        work_queue.task_done()


def enumerate_subdomains(
    base_domain: str,
    wordlist_path: str,
    threads: int = DEFAULT_THREADS,
    progress_callback: ProgressCallback | None = None,
    finding_callback: FindingCallback | None = None,
) -> SubdomainResult:
    """Run threaded subdomain brute-force enumeration."""
    started_at = time.perf_counter()
    normalized_domain = normalize_base_domain(base_domain)
    candidates = load_wordlist(wordlist_path)
    wildcard_ip = detect_wildcard_ip(normalized_domain)
    worker_count = max(1, min(int(threads), len(candidates) or 1))
    work_queue: queue.Queue[str] = queue.Queue()
    findings: list[SubdomainFinding] = []
    findings_lock = threading.Lock()
    progress_lock = threading.Lock()
    progress_state = {"completed": 0}

    for candidate in candidates:
        work_queue.put(candidate)

    workers = [
        threading.Thread(
            target=_worker,
            args=(
                normalized_domain,
                work_queue,
                findings,
                findings_lock,
                progress_state,
                progress_lock,
                len(candidates),
                wildcard_ip,
                progress_callback,
                finding_callback,
            ),
            daemon=True,
        )
        for _ in range(worker_count)
    ]

    for worker in workers:
        worker.start()

    for worker in workers:
        worker.join()

    findings.sort(key=lambda item: item.hostname)

    return SubdomainResult(
        base_domain=normalized_domain,
        wordlist_path=str(Path(wordlist_path)),
        tested_count=len(candidates),
        findings=tuple(findings),
        duration=time.perf_counter() - started_at,
    )
