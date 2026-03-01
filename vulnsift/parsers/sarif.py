"""SARIF 2.1.0 parser -> list of UnifiedFinding."""

from __future__ import annotations

import json
from pathlib import Path

from vulnsift.models import Location, UnifiedFinding


def parse_sarif(path: str | Path) -> list[UnifiedFinding]:
    """
    Parse a SARIF 2.1.0 file into a list of UnifiedFinding.
    Fails fast with clear errors on invalid or unsupported format.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"SARIF file not found: {path}")

    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in SARIF file: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("SARIF root must be a JSON object")

    version = data.get("version") or data.get("$schema", "")
    if "2.1" not in str(version) and "sarif" not in str(version).lower():
        raise ValueError(
            f"Unsupported SARIF version: {version}. VulnSift expects SARIF 2.1.0."
        )

    runs = data.get("runs")
    if not runs:
        return []

    findings: list[UnifiedFinding] = []
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            continue
        tool = run.get("tool", {}) or {}
        if isinstance(tool, dict):
            driver = tool.get("driver", {}) or {}
        else:
            driver = {}
        rules = _rules_by_id(driver.get("rules", []) or [])
        artifacts = run.get("artifacts", []) or []
        artifact_uris = _artifact_uris(artifacts)
        results = run.get("results", []) or []
        for res_index, result in enumerate(results):
            if not isinstance(result, dict):
                continue
            finding = _result_to_finding(
                result,
                run_index,
                res_index,
                rules,
                artifacts,
                artifact_uris,
            )
            findings.append(finding)

    return findings


def _rules_by_id(rules: list) -> dict:
    out: dict = {}
    for r in rules:
        if isinstance(r, dict) and r.get("id"):
            out[r["id"]] = r
    return out


def _artifact_uris(artifacts: list) -> dict[int, str]:
    uris: dict[int, str] = {}
    for i, a in enumerate(artifacts):
        if isinstance(a, dict) and "location" in a:
            loc = a["location"]
            if isinstance(loc, dict) and "uri" in loc:
                uris[i] = loc["uri"]
    return uris


def _get_message(obj: dict) -> str:
    """Extract message text from SARIF message object."""
    if not isinstance(obj, dict):
        return str(obj) if obj else ""
    if "text" in obj:
        return obj["text"] or ""
    if "markdown" in obj:
        return obj["markdown"] or ""
    return ""


def _result_to_finding(
    result: dict,
    run_index: int,
    res_index: int,
    rules: dict,
    artifacts: list,
    artifact_uris: dict[int, str],
) -> UnifiedFinding:
    rule_id = result.get("ruleId") or result.get("rule", "")
    rule = rules.get(rule_id, {}) if rule_id else {}
    short_desc = _get_message(rule.get("shortDescription", {})) or _get_message(
        rule.get("fullDescription", {})
    )
    msg = _get_message(result.get("message", {})) or short_desc or rule_id or "Finding"

    level = (result.get("level") or "").lower()
    severity = level if level in ("error", "warning", "note") else "warning"

    loc = Location()
    locations = result.get("locations", []) or []
    if locations and isinstance(locations[0], dict):
        ploc = locations[0].get("physicalLocation", {}) or {}
        if isinstance(ploc, dict):
            idx = ploc.get("artifactIndex")
            if idx is not None and idx in artifact_uris:
                loc.file_path = artifact_uris[idx]
            region = ploc.get("region", {}) or {}
            if isinstance(region, dict):
                loc.start_line = region.get("startLine")
                loc.end_line = region.get("endLine")
                if "snippet" in region and isinstance(region["snippet"], dict):
                    loc.snippet = region["snippet"].get("text")

    unique_id = f"sarif_run{run_index}_res{res_index}_{rule_id}"
    return UnifiedFinding(
        id=unique_id,
        rule_id=rule_id,
        title=short_desc or msg[:200],
        message=msg,
        severity=severity,
        description=_get_message(rule.get("fullDescription", {})) or short_desc,
        cve=None,
        cwe=None,
        location=loc,
        raw=result,
        source_format="sarif",
    )
