"""Parsers for SARIF and vendor scan formats -> UnifiedFinding."""

from pathlib import Path

from vulnsift.parsers.sarif import parse_sarif
from vulnsift.parsers.snyk import parse_snyk

__all__ = ["parse_sarif", "parse_snyk", "parse_scan_file"]


def parse_scan_file(path: str | Path, format: str) -> list:
    """Parse a scan file by format. Returns list of UnifiedFinding."""
    fmt = format.lower().strip()
    if fmt == "sarif":
        return parse_sarif(path)
    if fmt == "snyk":
        return parse_snyk(path)
    raise ValueError(f"Unsupported format: {format}. Use 'sarif' or 'snyk'.")
