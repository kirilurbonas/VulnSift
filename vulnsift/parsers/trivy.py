"""Trivy JSON parser -> list of UnifiedFinding.

Handles ``trivy <fs|image|repo|config> -f json`` output: ``Results[]`` with ``Target`` and any of
``Vulnerabilities[]``, ``Misconfigurations[]`` and ``Secrets[]``. ``Results`` may be null (clean scan).
The legacy (pre-SchemaVersion 2) top-level list of results is also accepted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnsift.models import Location, UnifiedFinding
from vulnsift.parsers._common import as_dict, dedupe_ids, extract_cves, extract_cwes, load_json, safe_id

_MAX_REFS_IN_DESCRIPTION = 5


def parse_trivy(path: str | Path) -> list[UnifiedFinding]:
    """
    Parse Trivy scan -f json output into a list of UnifiedFinding.
    Handles Results[] with Target and Vulnerabilities[] / Misconfigurations[] / Secrets[].
    """
    data = load_json(path, "Trivy")

    # Trivy can be a list of results (legacy) or an object with Results
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
        target = str(run_item.get("Target") or "")
        for v in _dicts(run_item.get("Vulnerabilities")):
            findings.append(_vuln_to_finding(v, target, run_item))
        for m in _dicts(run_item.get("Misconfigurations")):
            if str(m.get("Status") or "FAIL").upper() == "PASS":
                continue
            findings.append(_misconfig_to_finding(m, target, run_item))
        for s in _dicts(run_item.get("Secrets")):
            findings.append(_secret_to_finding(s, target, run_item))

    return dedupe_ids(findings)


def _dicts(value: Any) -> list[dict]:
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def _references(item: dict) -> list[str]:
    refs = item.get("References") or []
    out = [str(r) for r in refs if r] if isinstance(refs, list) else []
    primary = item.get("PrimaryURL")
    if primary:
        out = [str(primary)] + [r for r in out if r != primary]
    return out


def _with_references(text: str, refs: list[str]) -> str:
    if not refs:
        return text
    ref_block = "References:\n" + "\n".join(f"- {r}" for r in refs[:_MAX_REFS_IN_DESCRIPTION])
    return f"{text}\n\n{ref_block}" if text else ref_block


def _severity(item: dict) -> str:
    return str(item.get("Severity") or "UNKNOWN").lower()


def _code_snippet(item: dict) -> str | None:
    """Join CauseMetadata.Code.Lines (or Code.Lines for secrets), preferring the cause lines."""
    code = item.get("Code")
    cause_meta = item.get("CauseMetadata")
    if not isinstance(code, dict) and isinstance(cause_meta, dict):
        code = cause_meta.get("Code")
    lines = _dicts(code.get("Lines")) if isinstance(code, dict) else []
    if not lines:
        return None
    cause = [ln for ln in lines if ln.get("IsCause")] or lines
    text = "\n".join(str(ln.get("Content") or "") for ln in cause).rstrip()
    return text or None


def _result_meta(run_item: dict) -> dict:
    return {k: run_item.get(k) for k in ("Target", "Class", "Type") if run_item.get(k) is not None}


def _vuln_to_finding(v: dict, target: str, run_item: dict) -> UnifiedFinding:
    vuln_id = str(v.get("VulnerabilityID") or "")
    pkg_name = str(v.get("PkgName") or "")
    installed = str(v.get("InstalledVersion") or "")
    fixed = str(v.get("FixedVersion") or "")
    desc = str(v.get("Description") or "")
    vuln_title = str(v.get("Title") or "") or desc[:200] or vuln_id or pkg_name
    pkg_ref = f"{pkg_name}@{installed}" if installed else pkg_name

    title = f"{vuln_title} ({pkg_ref})" if pkg_ref and pkg_ref not in vuln_title else vuln_title
    fix_text = f"Fixed in {fixed}." if fixed else "No fixed version available."
    subject = " ".join(p for p in (pkg_name, installed) if p) or target or "Package"
    message = f"{subject} is affected by {vuln_id or vuln_title}"
    if vuln_title and vuln_title != vuln_id:
        message += f" ({vuln_title})"
    message += f". {fix_text}"

    refs = _references(v)
    cves = extract_cves([vuln_id, v.get("VendorIDs") or []])
    cwes = extract_cwes([v.get("CweIDs") or []])

    loc = Location(file_path=target, region=pkg_ref or None)
    if v.get("PkgPath"):
        loc.region = f"{pkg_ref} ({v['PkgPath']})"

    raw = dict(v)
    raw.update({"finding_type": "vulnerability", "references": refs, "result": _result_meta(run_item)})

    unique_id = safe_id(f"trivy_{target}_{vuln_id}_{pkg_ref}_{v.get('PkgPath') or ''}", max_len=160)
    return UnifiedFinding(
        id=unique_id,
        rule_id=vuln_id,
        title=title[:200],
        message=message,
        severity=_severity(v),
        description=_with_references(desc, refs),
        cve=cves[0] if cves else None,
        cwe=cwes[0] if cwes else None,
        location=loc,
        raw=raw,
        source_format="trivy",
    )


def _misconfig_to_finding(m: dict, target: str, run_item: dict) -> UnifiedFinding:
    rule_id = str(m.get("AVDID") or m.get("ID") or "")
    title = str(m.get("Title") or rule_id or "Misconfiguration")
    message = str(m.get("Message") or m.get("Description") or title)
    desc = str(m.get("Description") or "")
    if m.get("Resolution"):
        desc = (desc + "\n\n" if desc else "") + f"Resolution: {m['Resolution']}"
    refs = _references(m)

    cause = as_dict(m.get("CauseMetadata"))
    start = cause.get("StartLine")
    end = cause.get("EndLine")
    loc = Location(
        file_path=target,
        start_line=start if isinstance(start, int) and start > 0 else None,
        end_line=end if isinstance(end, int) and end > 0 else None,
        snippet=_code_snippet(m),
        region=str(cause.get("Resource")) if cause.get("Resource") else None,
    )

    raw = dict(m)
    raw.update({"finding_type": "misconfiguration", "references": refs, "result": _result_meta(run_item)})

    unique_id = safe_id(f"trivy_misconfig_{target}_{rule_id}_{loc.start_line or ''}_{loc.region or ''}", max_len=160)
    return UnifiedFinding(
        id=unique_id,
        rule_id=rule_id,
        title=title[:200],
        message=message,
        severity=_severity(m),
        description=_with_references(desc, refs),
        cwe=None,
        cve=None,
        location=loc,
        raw=raw,
        source_format="trivy",
    )


def _secret_to_finding(s: dict, target: str, run_item: dict) -> UnifiedFinding:
    rule_id = str(s.get("RuleID") or "")
    title = str(s.get("Title") or rule_id or "Secret")
    category = s.get("Category")
    message = f"Secret detected: {title}" + (f" ({category})" if category else "")
    start = s.get("StartLine")
    end = s.get("EndLine")
    # Trivy masks the secret value in Match and Code lines; never use anything else as the snippet.
    snippet = _code_snippet(s) or (str(s["Match"]) if s.get("Match") else None)
    loc = Location(
        file_path=target,
        start_line=start if isinstance(start, int) and start > 0 else None,
        end_line=end if isinstance(end, int) and end > 0 else None,
        snippet=snippet,
    )

    raw = dict(s)
    raw.update({"finding_type": "secret", "result": _result_meta(run_item)})

    unique_id = safe_id(f"trivy_secret_{target}_{rule_id}_{loc.start_line or ''}", max_len=160)
    return UnifiedFinding(
        id=unique_id,
        rule_id=rule_id,
        title=title[:200],
        message=message,
        severity=_severity(s),
        description=f"Hard-coded secret ({category or 'unknown category'}) found in {target}.",
        cwe="CWE-798",
        cve=None,
        location=loc,
        raw=raw,
        source_format="trivy",
    )
