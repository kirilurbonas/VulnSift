"""Snyk JSON parser -> list of UnifiedFinding."""

from __future__ import annotations

import json
from pathlib import Path

from vulnsift.models import Location, UnifiedFinding


def parse_snyk(path: str | Path) -> list[UnifiedFinding]:
    """
    Parse Snyk test --json output into a list of UnifiedFinding.
    Handles both vulnerability list and optional path/position when present.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Snyk file not found: {path}")

    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in Snyk file: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Snyk root must be a JSON object")

    vulnerabilities = data.get("vulnerabilities", []) or data.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        vulnerabilities = []

    findings: list[UnifiedFinding] = []
    for i, vuln in enumerate(vulnerabilities):
        if not isinstance(vuln, dict):
            continue
        finding = _vuln_to_finding(vuln, i)
        findings.append(finding)

    return findings


def _vuln_to_finding(vuln: dict, index: int) -> UnifiedFinding:
    title = vuln.get("title") or vuln.get("id", "")
    if isinstance(title, dict):
        title = title.get("title", str(title))
    title = str(title).strip() or "Snyk finding"

    description = vuln.get("description") or ""
    if isinstance(description, list):
        description = " ".join(str(d) for d in description)
    description = str(description).strip()

    severity = (vuln.get("severity") or "medium").lower()
    package_name = vuln.get("packageName") or vuln.get("name", "")
    version = vuln.get("version") or vuln.get("semver", {})
    if isinstance(version, dict):
        version = version.get("vulnerable", [""])
        version = version[0] if version else ""
    version = str(version)

    identifiers = vuln.get("identifiers", {}) or {}
    cve_list = identifiers.get("CVE", []) or []
    cwe_list = identifiers.get("CWE", []) or []
    cve = cve_list[0] if cve_list else None
    cwe = cwe_list[0] if cwe_list else None
    if isinstance(cve, list):
        cve = cve[0] if cve else None
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    cve = str(cve) if cve else None
    cwe = str(cwe) if cwe else None

    loc = Location()
    if "from" in vuln:
        from_val = vuln["from"]
        if isinstance(from_val, list):
            loc.region = " -> ".join(str(p) for p in from_val)
        else:
            loc.region = str(from_val)
    if "package" in vuln:
        loc.file_path = str(vuln.get("package", ""))

    unique_id = f"snyk_{index}_{package_name}_{cve or title[:30]}".replace(" ", "_")
    return UnifiedFinding(
        id=unique_id,
        rule_id=vuln.get("id", ""),
        title=title,
        message=description or title,
        severity=severity,
        description=description,
        cve=cve,
        cwe=cwe,
        location=loc,
        raw=vuln,
        source_format="snyk",
    )
