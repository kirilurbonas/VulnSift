"""Parsers for SARIF and vendor scan formats -> UnifiedFinding."""

from pathlib import Path

from vulnsift.parsers.sarif import parse_sarif
from vulnsift.parsers.semgrep import parse_semgrep
from vulnsift.parsers.snyk import parse_snyk
from vulnsift.parsers.trivy import parse_trivy

__all__ = [
    "parse_sarif",
    "parse_snyk",
    "parse_semgrep",
    "parse_trivy",
    "parse_scan_file",
    "detect_format",
]

SUPPORTED_FORMATS = ("sarif", "snyk", "semgrep", "trivy")


def detect_format(path: str | Path) -> str:
    """
    Detect scan format from file path and/or content. Returns one of sarif, snyk, semgrep, trivy.
    Raises ValueError if format cannot be determined.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        import json
        data = json.loads(raw)
    except Exception as err:
        raise ValueError(f"Cannot parse as JSON: {path}") from err

    if not isinstance(data, dict):
        # Trivy can be a list
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and ("Results" in item or "Target" in item or "Vulnerabilities" in item):
                    return "trivy"
        raise ValueError("Unknown format: root is not an object")

    # SARIF
    if data.get("$schema", "").lower().find("sarif") >= 0 or data.get("version") == "2.1.0":
        runs = data.get("runs")
        if isinstance(runs, list):
            return "sarif"

    # Snyk
    if "vulnerabilities" in data and isinstance(data.get("vulnerabilities"), list):
        return "snyk"

    # Semgrep
    if "results" in data and isinstance(data.get("results"), list):
        return "semgrep"

    # Trivy (object with Results)
    if "Results" in data and isinstance(data.get("Results"), list):
        return "trivy"

    raise ValueError(f"Could not detect format for {path}. Use --format sarif|snyk|semgrep|trivy.")


def parse_scan_file(path: str | Path, format: str) -> list:
    """Parse a scan file by format. Returns list of UnifiedFinding. format may be 'auto' to detect."""
    fmt = format.lower().strip()
    if fmt == "auto":
        fmt = detect_format(path)
    if fmt == "sarif":
        return parse_sarif(path)
    if fmt == "snyk":
        return parse_snyk(path)
    if fmt == "semgrep":
        return parse_semgrep(path)
    if fmt == "trivy":
        return parse_trivy(path)
    raise ValueError(f"Unsupported format: {format}. Use one of: {', '.join(SUPPORTED_FORMATS)}, or 'auto'.")
