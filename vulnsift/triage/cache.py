"""MVP triage cache: skip API calls for unchanged findings (same fingerprint + prompt + redact flag)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from vulnsift.models import RemediationCard, TriageReportEntry, TriageResult, UnifiedFinding

CACHE_FILE_VERSION = "1"


def fingerprint(finding: UnifiedFinding, prompt_version: str, redact_code: bool) -> str:
    """Stable hash for cache lookup."""
    payload = {
        "pv": prompt_version,
        "rc": redact_code,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "message": finding.message,
        "severity": finding.severity,
        "description": finding.description,
        "cve": finding.cve,
        "cwe": finding.cwe,
        "file_path": finding.location.file_path,
        "start_line": finding.location.start_line,
        "snippet": finding.location.snippet,
        "source_format": finding.source_format,
    }
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_cache(path: Path, expected_prompt_version: str) -> dict[str, dict[str, Any]]:
    """Load cache dict fingerprint -> {triage, remediation}. Empty if invalid or prompt mismatch."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    if data.get("file_version") != CACHE_FILE_VERSION:
        return {}
    if data.get("prompt_version") != expected_prompt_version:
        return {}
    entries = data.get("entries")
    if not isinstance(entries, dict):
        return {}
    return {str(k): v for k, v in entries.items() if isinstance(v, dict)}


def save_cache(
    path: Path,
    entries_map: dict[str, dict[str, Any]],
    prompt_version: str,
) -> None:
    """Write cache to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "file_version": CACHE_FILE_VERSION,
        "prompt_version": prompt_version,
        "entries": entries_map,
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def cache_entry_to_report_entry(finding: UnifiedFinding, cached: dict[str, Any]) -> TriageReportEntry | None:
    """Rebuild TriageReportEntry from cached triage/remediation dicts."""
    try:
        tri_raw = cached.get("triage")
        rem_raw = cached.get("remediation")
        if not isinstance(tri_raw, dict):
            return None
        triage = TriageResult.model_validate(tri_raw)
        remediation = RemediationCard.model_validate(rem_raw) if isinstance(rem_raw, dict) else None
        return TriageReportEntry(finding=finding, triage=triage, remediation=remediation)
    except Exception:
        return None


def report_entry_to_cache_dict(entry: TriageReportEntry) -> dict[str, Any]:
    """Serialize entry triage + remediation for cache."""
    return {
        "triage": entry.triage.model_dump(mode="json"),
        "remediation": entry.remediation.model_dump(mode="json") if entry.remediation else None,
    }
