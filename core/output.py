"""Output path resolution and report persistence helpers."""

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
import re


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "output"
DEFAULT_TCP_TEXT_ARGUMENT = "hylianscan_results.txt"
DEFAULT_TCP_JSON_ARGUMENT = "hylianscan_tcp_results.json"
TCP_REPORT_FILENAME = "tcp_report.txt"
TCP_JSON_FILENAME = "tcp_results.json"
SUBDOMAIN_REPORT_FILENAME = "subdomains.txt"
SUBDOMAIN_JSON_FILENAME = "subdomains.json"
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def build_timestamp() -> str:
    """Return the default UTC timestamp used for output workspaces."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def sanitize_target_name(target: str) -> str:
    """Convert a target value into a safe output directory name."""
    normalized = target.strip().lower()
    sanitized = re.sub(r"[^a-z0-9._-]+", "_", normalized)
    sanitized = re.sub(r"_+", "_", sanitized).strip("._-")

    return sanitized[:120] or "target"


def resolve_output_workspace(
    target: str,
    timestamp: str | None = None,
    timestamp_factory: Callable[[], str] = build_timestamp,
) -> Path:
    """Resolve the target-specific timestamped output workspace directory."""
    timestamp_value = timestamp or timestamp_factory()
    return OUTPUT_DIR / sanitize_target_name(target) / timestamp_value


def is_default_tcp_text_output_request(output_value: str | None) -> bool:
    """Return True when TCP text output was requested without an explicit path."""
    return output_value in ("", DEFAULT_TCP_TEXT_ARGUMENT)


def is_default_tcp_json_output_request(output_value: str | None) -> bool:
    """Return True when TCP JSON output was requested without an explicit path."""
    return output_value in ("", DEFAULT_TCP_JSON_ARGUMENT)


def should_create_tcp_output_workspace(
    output_value: str | None,
    json_output_value: str | None,
) -> bool:
    """Return True when TCP output should use a timestamped workspace."""
    return is_default_tcp_text_output_request(
        output_value
    ) or is_default_tcp_json_output_request(json_output_value)


def should_create_passive_output_workspace(
    output_value: str | None,
    json_output_value: str | None,
) -> bool:
    """Return True when passive output should use a timestamped workspace."""
    return (
        output_value is None
        or is_default_tcp_text_output_request(output_value)
        or is_default_tcp_json_output_request(json_output_value)
    )


def resolve_output_path(
    output_value: str | None,
    workspace_dir: Path | None = None,
) -> Path | None:
    """Resolve a TCP text output filename inside the local output directory."""
    if output_value is None:
        return None

    if workspace_dir is not None and is_default_tcp_text_output_request(output_value):
        return workspace_dir / TCP_REPORT_FILENAME

    safe_filename = Path(output_value).name or DEFAULT_TCP_TEXT_ARGUMENT
    return OUTPUT_DIR / safe_filename


def resolve_json_output_path(
    output_value: str | None,
    workspace_dir: Path | None = None,
) -> Path | None:
    """Resolve a TCP JSON output filename inside the local output directory."""
    if output_value is None:
        return None

    if workspace_dir is not None and is_default_tcp_json_output_request(output_value):
        return workspace_dir / TCP_JSON_FILENAME

    safe_filename = Path(output_value).name or DEFAULT_TCP_JSON_ARGUMENT

    if Path(safe_filename).suffix.lower() != ".json":
        safe_filename = f"{safe_filename}.json"

    return OUTPUT_DIR / safe_filename


def resolve_subdomain_json_output_path(
    output_value: str | None,
    workspace_dir: Path | None = None,
) -> Path | None:
    """Resolve a passive subdomain JSON output filename inside output/."""
    if output_value is None:
        return None

    if workspace_dir is not None and is_default_tcp_json_output_request(output_value):
        return workspace_dir / SUBDOMAIN_JSON_FILENAME

    safe_filename = Path(output_value).name or "hylianscan_subdomains.json"

    if safe_filename == DEFAULT_TCP_JSON_ARGUMENT:
        safe_filename = "hylianscan_subdomains.json"

    if Path(safe_filename).suffix.lower() != ".json":
        safe_filename = f"{safe_filename}.json"

    return OUTPUT_DIR / safe_filename


def resolve_subdomain_output_path(
    output_value: str | None,
    workspace_dir: Path | None = None,
) -> Path:
    """Resolve the mandatory passive subdomain TXT output file path."""
    if workspace_dir is not None and (
        output_value is None or is_default_tcp_text_output_request(output_value)
    ):
        return workspace_dir / SUBDOMAIN_REPORT_FILENAME

    if output_value is None:
        return OUTPUT_DIR / "hylianscan_subdomains.txt"

    if output_value == DEFAULT_TCP_TEXT_ARGUMENT:
        return OUTPUT_DIR / SUBDOMAIN_REPORT_FILENAME

    requested_dir = Path(output_value).expanduser()

    if not requested_dir.is_absolute():
        requested_dir = PROJECT_ROOT / requested_dir

    return requested_dir / "subdomains.txt"


def save_report(report_text: str, output_path: Path | None) -> None:
    """Persist a TCP text report when requested by the operator."""
    if output_path is None:
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    plain_report = ANSI_ESCAPE_PATTERN.sub("", report_text)
    output_path.write_text(plain_report + "\n", encoding="utf-8")


def save_subdomain_results(subdomains: list[str], output_path: Path) -> None:
    """Persist passive subdomain results without flooding the terminal."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(subdomains) + "\n", encoding="utf-8")
