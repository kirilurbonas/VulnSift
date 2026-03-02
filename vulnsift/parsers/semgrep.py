"""Semgrep JSON parser -> list of UnifiedFinding."""

from __future__ import annotations

import json
from pathlib import Path

from vulnsift.models import Location, UnifiedFinding


def parse_semgrep(path: str | Path) -> list[UnifiedFinding]:
    """
    Parse Semgrep scan --json output into a list of UnifiedFinding.
    Expects top-level keys: results, paths (with _comment or scanned), errors, version.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Semgrep file not found: {path}")

    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in Semgrep file: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Semgrep root must be a JSON object")

    results = data.get("results") or []
    if not isinstance(results, list):
        results = []

    # Build path index: Semgrep uses path as string or index into paths.scanned
    paths_scanned = data.get("paths", {})
    if isinstance(paths_scanned, dict) and "scanned" in paths_scanned:
        path_list = paths_scanned.get("scanned") or []
    else:
        path_list = []

    findings: list[UnifiedFinding] = []
    for i, res in enumerate(results):
        if not isinstance(res, dict):
            continue
        finding = _result_to_finding(res, i, path_list)
        findings.append(finding)

    return findings


def _result_to_finding(res: dict, index: int, path_list: list) -> UnifiedFinding:
    check_id = res.get("check_id") or res.get("rule_id") or ""
    path_val = res.get("path")
    if path_val is not None and isinstance(path_val, int) and 0 <= path_val < len(path_list):
        file_path = str(path_list[path_val])
    else:
        file_path = str(path_val) if path_val else ""

    extra = res.get("extra") or {}
    if isinstance(extra, dict):
        message = extra.get("message") or ""
        severity = (extra.get("severity") or "WARNING").upper()
        metadata = extra.get("metadata") or {}
    else:
        message = ""
        severity = "WARNING"
        metadata = {}

    if isinstance(metadata, dict):
        cwe = metadata.get("cwe")
        cve = metadata.get("cve")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        if isinstance(cve, list):
            cve = cve[0] if cve else None
        cwe = str(cwe) if cwe else None
        cve = str(cve) if cve else None
    else:
        cwe = None
        cve = None

    start = res.get("start") or {}
    end = res.get("end") or {}
    if isinstance(start, dict):
        start_line = start.get("line")
    else:
        start_line = None
    if isinstance(end, dict):
        end_line = end.get("line")
    else:
        end_line = None

    loc = Location(
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
    )

    unique_id = f"semgrep_{index}_{check_id}".replace("/", "_")[:80]
    return UnifiedFinding(
        id=unique_id,
        rule_id=check_id,
        title=message[:200] if message else check_id,
        message=message,
        severity=severity.lower() if isinstance(severity, str) else "warning",
        description=message,
        cve=cve,
        cwe=cwe,
        location=loc,
        raw=res,
        source_format="semgrep",
    )
