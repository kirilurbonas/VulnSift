"""Parsers for SARIF and vendor scan formats -> UnifiedFinding."""

from pathlib import Path
from typing import Any

from vulnsift.parsers._common import load_json
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
    "SUPPORTED_FORMATS",
]

SUPPORTED_FORMATS = ("sarif", "snyk", "semgrep", "trivy")


def detect_format(path: str | Path) -> str:
    """
    Detect scan format from file content. Returns one of sarif, snyk, semgrep, trivy.
    Raises FileNotFoundError if the file is missing and ValueError if it is not JSON or not recognised.
    """
    path = Path(path)
    data = load_json(path, "scan")
    fmt = _detect_from_data(data)
    if fmt is None:
        raise ValueError(
            f"Could not detect scan format for {path}. Supported formats: {', '.join(SUPPORTED_FORMATS)} "
            "(SARIF 2.1.0, `snyk test --json`, `semgrep --json`, `trivy -f json`). "
            "Pass --format sarif|snyk|semgrep|trivy to force one."
        )
    return fmt


def _detect_from_data(data: Any) -> str | None:
    if isinstance(data, list):
        items = [x for x in data if isinstance(x, dict)]
        # Snyk --all-projects: list of project objects
        if items and all(_is_snyk(x) for x in items):
            return "snyk"
        # Legacy Trivy: list of results with Target
        if any(
            "Target" in x
            and ("Vulnerabilities" in x or "Misconfigurations" in x or "Secrets" in x or "Type" in x or "Class" in x)
            for x in items
        ):
            return "trivy"
        return None
    if not isinstance(data, dict):
        return None

    # SARIF: $schema mentions sarif, or version + runs[]
    schema = str(data.get("$schema") or "").lower()
    runs = data.get("runs")
    if isinstance(runs, list) and ("sarif" in schema or str(data.get("version") or "").startswith("2.")):
        return "sarif"

    # Trivy: SchemaVersion / ArtifactName, or Results[] (possibly null) whose items have Target
    results_upper = data.get("Results")
    if "SchemaVersion" in data and ("Results" in data or "ArtifactName" in data):
        return "trivy"
    if isinstance(results_upper, list) and all(isinstance(r, dict) and "Target" in r for r in results_upper):
        return "trivy"

    # Semgrep: results[] whose items have check_id (or empty results alongside errors/paths/version)
    results = data.get("results")
    if isinstance(results, list):
        if any(isinstance(r, dict) and "check_id" in r for r in results):
            return "semgrep"
        if not results and ("paths" in data or "errors" in data):
            return "semgrep"

    if _is_snyk(data):
        return "snyk"
    return None


def _is_snyk(obj: dict) -> bool:
    if isinstance(obj.get("vulnerabilities"), list):
        return True
    # Errored / clean Snyk project entries
    return "packageManager" in obj and ("ok" in obj or "dependencyCount" in obj)


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
