"""Trivy JSON parser -> list of UnifiedFinding."""

from __future__ import annotations

import json
from pathlib import Path

from vulnsift.models import Location, UnifiedFinding


def parse_trivy(path: str | Path) -> list[UnifiedFinding]:
    """
    Parse Trivy scan -f json output into a list of UnifiedFinding.
    Handles Results[] with Target and Vulnerabilities[] (fs, image, etc.).
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Trivy file not found: {path}")

    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in Trivy file: {e}") from e

    # Trivy can be a list of results or an object with Results
    if isinstance(data, list):
        results = data
    elif isinstance(data, dict):
        results = data.get("Results") or []
    else:
        raise ValueError("Trivy root must be a JSON object or array")

    if not isinstance(results, list):
        results = []

    findings: list[UnifiedFinding] = []
    for run_item in results:
        if not isinstance(run_item, dict):
            continue
        target = run_item.get("Target") or ""
        vulns = run_item.get("Vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for i, v in enumerate(vulns):
            if not isinstance(v, dict):
                continue
            finding = _vuln_to_finding(v, str(target), i)
            findings.append(finding)

    return findings


def _vuln_to_finding(v: dict, target: str, index: int) -> UnifiedFinding:
    vuln_id = v.get("VulnerabilityID") or ""
    pkg_name = v.get("PkgName") or ""
    severity = (v.get("Severity") or "UNKNOWN").upper()
    desc = v.get("Description") or ""
    title = v.get("Title") or desc[:200] or vuln_id or pkg_name

    refs = v.get("References") or []
    if isinstance(refs, list):
        ref_links = [str(r) for r in refs[:5]]
    else:
        ref_links = []

    primary_url = v.get("PrimaryURL")
    if primary_url and primary_url not in ref_links:
        ref_links = [primary_url] + ref_links

    loc = Location(file_path=target, region=f"{pkg_name}@{v.get('InstalledVersion', '')}")

    unique_id = f"trivy_{index}_{target}_{vuln_id}".replace("/", "_")[:80]
    return UnifiedFinding(
        id=unique_id,
        rule_id=vuln_id,
        title=title[:200] if title else vuln_id,
        message=desc or title,
        severity=severity.lower() if isinstance(severity, str) else "unknown",
        description=desc,
        cve=vuln_id if vuln_id.startswith("CVE-") else None,
        cwe=None,
        location=loc,
        raw=v,
        source_format="trivy",
    )
