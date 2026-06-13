"""Output path resolution and report persistence helpers."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "output"


def resolve_output_path(output_value: str | None) -> Path | None:
    """Resolve a TCP text output filename inside the local output directory."""
    if output_value is None:
        return None

    safe_filename = Path(output_value).name or "hylianscan_results.txt"
    return OUTPUT_DIR / safe_filename


def resolve_json_output_path(output_value: str | None) -> Path | None:
    """Resolve a TCP JSON output filename inside the local output directory."""
    if output_value is None:
        return None

    safe_filename = Path(output_value).name or "hylianscan_tcp_results.json"

    if Path(safe_filename).suffix.lower() != ".json":
        safe_filename = f"{safe_filename}.json"

    return OUTPUT_DIR / safe_filename


def resolve_subdomain_json_output_path(output_value: str | None) -> Path | None:
    """Resolve a passive subdomain JSON output filename inside output/."""
    if output_value is None:
        return None

    safe_filename = Path(output_value).name or "hylianscan_subdomains.json"

    if safe_filename == "hylianscan_tcp_results.json":
        safe_filename = "hylianscan_subdomains.json"

    if Path(safe_filename).suffix.lower() != ".json":
        safe_filename = f"{safe_filename}.json"

    return OUTPUT_DIR / safe_filename


def resolve_subdomain_output_path(output_value: str | None) -> Path:
    """Resolve the mandatory passive subdomain TXT output file path."""
    if output_value is None:
        return OUTPUT_DIR / "hylianscan_subdomains.txt"

    if output_value == "hylianscan_results.txt":
        return OUTPUT_DIR / "subdomains.txt"

    requested_dir = Path(output_value).expanduser()

    if not requested_dir.is_absolute():
        requested_dir = PROJECT_ROOT / requested_dir

    return requested_dir / "subdomains.txt"


def save_report(report_text: str, output_path: Path | None) -> None:
    """Persist a TCP text report when requested by the operator."""
    if output_path is None:
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_text + "\n", encoding="utf-8")


def save_subdomain_results(subdomains: list[str], output_path: Path) -> None:
    """Persist passive subdomain results without flooding the terminal."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(subdomains) + "\n", encoding="utf-8")
