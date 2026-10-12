"""Semgrep JSON parser -> list of UnifiedFinding."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnsift.models import Location, UnifiedFinding
from vulnsift.parsers._common import as_dict, dedupe_ids, extract_cves, extract_cwes, load_json, safe_id, short_hash

# Semgrep rule severities -> VulnSift scanner severity. Newer rules may already use critical/high/...
SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "INVENTORY": "info",
    "EXPERIMENT": "info",
}
# Placeholder Semgrep emits for `lines` / `fingerprint` when not logged in.
_LOGIN_PLACEHOLDER = "requires login"


def parse_semgrep(path: str | Path) -> list[UnifiedFinding]:
    """
    Parse Semgrep scan --json output into a list of UnifiedFinding.
    Expects top-level keys: results, paths (with _comment or scanned), errors, version.
    """
    data = load_json(path, "Semgrep")

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
        findings.append(_result_to_finding(res, i, path_list))

    return dedupe_ids(findings)


def map_severity(value: Any) -> str:
    sev = str(value or "WARNING").upper()
    return SEVERITY_MAP.get(sev, sev.lower())


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _result_to_finding(res: dict, index: int, path_list: list) -> UnifiedFinding:
    check_id = str(res.get("check_id") or res.get("rule_id") or "")
    path_val = res.get("path")
    if path_val is not None and isinstance(path_val, int) and 0 <= path_val < len(path_list):
        file_path = str(path_list[path_val])
    else:
        file_path = str(path_val) if path_val else ""

    extra = as_dict(res.get("extra"))
    message = str(extra.get("message") or "").strip()
    scanner_severity = extra.get("severity") or "WARNING"
    metadata = as_dict(extra.get("metadata"))

    cwes = extract_cwes(_as_list(metadata.get("cwe")))
    cves = extract_cves([*_as_list(metadata.get("cve")), *_as_list(metadata.get("cves")), check_id])
    owasp = [str(o) for o in _as_list(metadata.get("owasp")) if o]
    references = [str(r) for r in _as_list(metadata.get("references")) if r]
    if metadata.get("source"):
        references.append(str(metadata["source"]))

    start = as_dict(res.get("start"))
    end = as_dict(res.get("end"))
    start_line = start.get("line") if isinstance(start.get("line"), int) else None
    end_line = end.get("line") if isinstance(end.get("line"), int) else start_line

    snippet = extra.get("lines")
    snippet = str(snippet).rstrip("\n") if snippet and str(snippet).strip() != _LOGIN_PLACEHOLDER else None

    loc = Location(file_path=file_path, start_line=start_line, end_line=end_line, snippet=snippet)

    desc_lines = [message] if message else []
    detail = []
    if cwes:
        detail.append("CWE: " + ", ".join(str(c) for c in _as_list(metadata.get("cwe"))))
    if owasp:
        detail.append(f"OWASP: {', '.join(owasp)}")
    for key in ("category", "confidence", "likelihood", "impact"):
        if metadata.get(key):
            detail.append(f"{key.capitalize()}: {metadata[key]}")
    if extra.get("fix"):
        detail.append(f"Suggested fix: {extra['fix']}")
    if references:
        detail.append("References:\n" + "\n".join(f"- {r}" for r in references[:5]))
    description = "\n\n".join([*desc_lines, "\n".join(detail)] if detail else desc_lines)

    fingerprint = extra.get("fingerprint")
    if fingerprint and str(fingerprint) != _LOGIN_PLACEHOLDER:
        key = short_hash(check_id, file_path, fingerprint)
    else:
        key = short_hash(check_id, file_path, start_line, start.get("col"), message)
    unique_id = safe_id(f"semgrep_{check_id.rsplit('.', 1)[-1]}_{key}")

    raw = dict(res)
    raw.update(
        {
            "scanner_severity": scanner_severity,
            "cwes": cwes,
            "cves": cves,
            "owasp": owasp,
            "references": references,
        }
    )

    return UnifiedFinding(
        id=unique_id,
        rule_id=check_id,
        title=message.splitlines()[0][:200] if message else check_id,
        message=message or check_id,
        severity=map_severity(scanner_severity),
        description=description,
        cve=cves[0] if cves else None,
        cwe=cwes[0] if cwes else None,
        location=loc,
        raw=raw,
        source_format="semgrep",
    )
