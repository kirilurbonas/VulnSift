"""SARIF 2.1.0 export of a triage report (e.g. for GitHub code scanning upload)."""

from __future__ import annotations

import json
from pathlib import Path

from vulnsift import __version__
from vulnsift.models import TriageReport, TriageReportEntry, risk_band

_LEVELS = {"high": "error", "medium": "warning", "low": "note"}


def _result(entry: TriageReportEntry, rule_index: int) -> dict:
    f = entry.finding
    t = entry.triage
    card = entry.remediation
    text = card.title if card and card.title else (f.title or f.message or f.rule_id)
    if t.reasoning:
        text = f"{text} — {t.reasoning}"
    result: dict = {
        "ruleId": f.rule_id or f.id,
        "ruleIndex": rule_index,
        "level": "warning" if t.is_error else _LEVELS[risk_band(t.risk_score)],
        "message": {"text": text},
        "properties": {
            "vulnsift-risk-score": t.risk_score,
            "vulnsift-likely-false-positive": t.is_likely_false_positive,
            "scanner-severity": f.severity,
            "source-format": f.source_format,
        },
    }
    if f.id:
        result["partialFingerprints"] = {"vulnsiftFindingId/v1": f.id}
    if t.is_error:
        result["properties"]["vulnsift-error"] = t.error
    if t.confidence is not None:
        result["properties"]["vulnsift-confidence"] = t.confidence
    if f.location.file_path:
        region: dict = {}
        if f.location.start_line:
            region["startLine"] = f.location.start_line
            if f.location.end_line and f.location.end_line >= f.location.start_line:
                region["endLine"] = f.location.end_line
        physical: dict = {"artifactLocation": {"uri": f.location.file_path.replace("\\", "/")}}
        if region:
            physical["region"] = region
        result["locations"] = [{"physicalLocation": physical}]
    if entry.is_false_positive:
        result["suppressions"] = [
            {"kind": "external", "status": "accepted", "justification": t.reasoning or "Likely false positive"}
        ]
    return result


def _rule(entry: TriageReportEntry) -> dict:
    f = entry.finding
    rule: dict = {
        "id": f.rule_id or f.id,
        "shortDescription": {"text": (f.title or f.rule_id or f.id)[:1000]},
        "properties": {"tags": ["security"]},
    }
    if f.description:
        rule["fullDescription"] = {"text": f.description[:4000]}
    if entry.remediation and entry.remediation.steps:
        steps = "\n".join(f"{i}. {s}" for i, s in enumerate(entry.remediation.steps, 1))
        rule["help"] = {"text": steps, "markdown": steps}
    if f.cwe:
        rule["properties"]["tags"].append(f.cwe)
    if not entry.triage.is_error:
        # GitHub code scanning maps this 0-10 number onto its own severity scale.
        rule["properties"]["security-severity"] = f"{float(entry.triage.risk_score):.1f}"
    return rule


def report_to_sarif(report: TriageReport) -> dict:
    rules: list[dict] = []
    rule_ids: dict[str, int] = {}
    results: list[dict] = []
    for entry in report.entries:
        rid = entry.finding.rule_id or entry.finding.id
        if rid not in rule_ids:
            rule_ids[rid] = len(rules)
            rules.append(_rule(entry))
        results.append(_result(entry, rule_ids[rid]))
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnSift",
                        "version": __version__,
                        "informationUri": "https://github.com/kirilurbonas/VulnSift",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {"model": report.model, "promptVersion": report.prompt_version},
            }
        ],
    }


def export_report_sarif(report: TriageReport, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report_to_sarif(report), indent=2), encoding="utf-8")
    return path
