"""Shared report analytics for CLI summaries, comparisons, and dashboards."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable

from vulnsift.models import TriageReport, TriageReportEntry


def actionable_entries(report: TriageReport) -> list[TriageReportEntry]:
    """Return findings that are not marked as likely false positives."""
    return [entry for entry in report.entries if not entry.triage.is_likely_false_positive]


def summarize_report(report: TriageReport) -> dict[str, object]:
    """Compute high-signal summary metrics for a triage report."""
    actionable = actionable_entries(report)
    fp_count = len(report.entries) - len(actionable)
    risk_scores = [entry.triage.risk_score for entry in actionable]
    source_formats = Counter((entry.finding.source_format or "unknown") for entry in report.entries)
    scanner_severities = Counter((entry.finding.severity or "unknown").lower() for entry in report.entries)

    return {
        "total_findings": len(report.entries),
        "actionable_findings": len(actionable),
        "false_positives": fp_count,
        "highest_risk": max(risk_scores, default=0),
        "average_risk": round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0.0,
        "risk_bands": {
            "high": sum(1 for score in risk_scores if score >= 7),
            "medium": sum(1 for score in risk_scores if 4 <= score < 7),
            "low": sum(1 for score in risk_scores if score < 4),
        },
        "source_formats": dict(sorted(source_formats.items())),
        "scanner_severities": dict(sorted(scanner_severities.items())),
        "total_risk": sum(risk_scores),
    }


def get_hotspots(report: TriageReport, limit: int = 5) -> list[dict[str, object]]:
    """Return the riskiest files, ranked by concentrated actionable risk."""
    grouped: dict[str, list[TriageReportEntry]] = defaultdict(list)
    for entry in actionable_entries(report):
        path = entry.finding.location.file_path or "(unknown file)"
        grouped[path].append(entry)

    hotspots: list[dict[str, object]] = []
    for file_path, entries in grouped.items():
        scores = [entry.triage.risk_score for entry in entries]
        hotspots.append(
            {
                "file_path": file_path,
                "finding_count": len(entries),
                "high_risk_count": sum(1 for score in scores if score >= 7),
                "max_risk": max(scores, default=0),
                "avg_risk": round(sum(scores) / len(scores), 1) if scores else 0.0,
                "total_risk": sum(scores),
                "top_rule_ids": sorted({entry.finding.rule_id for entry in entries if entry.finding.rule_id})[:3],
            }
        )

    hotspots.sort(
        key=lambda item: (
            -int(item["total_risk"]),
            -int(item["max_risk"]),
            -int(item["finding_count"]),
            str(item["file_path"]),
        )
    )
    return hotspots[: max(limit, 0)]


def get_priority_findings(
    report: TriageReport,
    limit: int = 5,
    *,
    min_risk: float = 4,
) -> list[dict[str, object]]:
    """Return the most urgent actionable findings with fix metadata."""
    backlog_items = get_backlog_items(report, limit=limit, min_risk=min_risk)
    priorities: list[dict[str, object]] = []
    for item in backlog_items:
        priorities.append(
            {
                "finding_id": item["finding_id"],
                "rule_id": item["rule_id"],
                "title": item["title"],
                "file_path": item["file_path"],
                "line": item["line"],
                "risk_score": item["risk_score"],
                "remediation_title": item["remediation_title"],
                "step_count": item["step_count"],
                "has_remediation": item["has_remediation"],
            }
        )
    return priorities


def get_backlog_items(
    report: TriageReport,
    limit: int | None = None,
    *,
    min_risk: float = 4,
) -> list[dict[str, object]]:
    """Return a prioritized backlog export with enough detail for tickets and reports."""
    priorities: list[dict[str, object]] = []
    for entry in actionable_entries(report):
        if entry.triage.risk_score < min_risk:
            continue
        remediation_steps = len(entry.remediation.steps) if entry.remediation else 0
        priorities.append(
            {
                "finding_id": entry.finding.id,
                "rule_id": entry.finding.rule_id,
                "title": entry.finding.title,
                "file_path": entry.finding.location.file_path or "(unknown file)",
                "line": entry.finding.location.start_line,
                "risk_score": entry.triage.risk_score,
                "remediation_title": entry.remediation.title if entry.remediation else None,
                "step_count": remediation_steps,
                "has_remediation": entry.remediation is not None,
                "business_impact": entry.remediation.business_impact if entry.remediation else "",
                "recommended_steps": list(entry.remediation.steps) if entry.remediation else [],
                "references": list(entry.remediation.reference_links) if entry.remediation else [],
                "cwe": entry.finding.cwe,
                "cve": entry.finding.cve,
                "severity": entry.finding.severity,
                "source_format": entry.finding.source_format,
            }
        )

    priorities.sort(
        key=lambda item: (
            -int(item["risk_score"]),
            not bool(item["has_remediation"]),
            int(item["step_count"]) if int(item["step_count"]) > 0 else 99,
            str(item["file_path"]),
            str(item["finding_id"]),
        )
    )
    if limit is None:
        return priorities
    return priorities[: max(limit, 0)]


def compare_reports(current: TriageReport, baseline: TriageReport) -> dict[str, object]:
    """Compare two reports and return actionable regression/progress insights."""
    current_summary = summarize_report(current)
    baseline_summary = summarize_report(baseline)

    current_map = _entry_map(actionable_entries(current))
    baseline_map = _entry_map(actionable_entries(baseline))

    current_keys = set(current_map)
    baseline_keys = set(baseline_map)

    new_keys = current_keys - baseline_keys
    resolved_keys = baseline_keys - current_keys
    persisting_keys = current_keys & baseline_keys

    new_entries = sorted(
        (_entry_snapshot(current_map[key]) for key in new_keys),
        key=lambda item: (-int(item["risk_score"]), str(item["file_path"]), str(item["rule_id"])),
    )
    resolved_entries = sorted(
        (_entry_snapshot(baseline_map[key]) for key in resolved_keys),
        key=lambda item: (-int(item["risk_score"]), str(item["file_path"]), str(item["rule_id"])),
    )

    risk_changes: list[dict[str, object]] = []
    for key in persisting_keys:
        current_entry = current_map[key]
        baseline_entry = baseline_map[key]
        delta = current_entry.triage.risk_score - baseline_entry.triage.risk_score
        snapshot = _entry_snapshot(current_entry)
        snapshot["baseline_risk"] = baseline_entry.triage.risk_score
        snapshot["risk_delta"] = delta
        risk_changes.append(snapshot)

    escalated = sorted(
        (item for item in risk_changes if int(item["risk_delta"]) > 0),
        key=lambda item: (-int(item["risk_delta"]), -int(item["risk_score"]), str(item["file_path"])),
    )
    improved = sorted(
        (item for item in risk_changes if int(item["risk_delta"]) < 0),
        key=lambda item: (int(item["risk_delta"]), -int(item["baseline_risk"]), str(item["file_path"])),
    )

    risk_delta = int(current_summary["total_risk"]) - int(baseline_summary["total_risk"])
    actionable_delta = int(current_summary["actionable_findings"]) - int(baseline_summary["actionable_findings"])
    new_high_risk = sum(1 for item in new_entries if int(item["risk_score"]) >= 7)
    resolved_high_risk = sum(1 for item in resolved_entries if int(item["risk_score"]) >= 7)

    if not new_entries and not resolved_entries and risk_delta == 0:
        trend = "stable"
    elif new_high_risk > resolved_high_risk or actionable_delta > 0 or risk_delta > 0:
        trend = "worsened"
    elif resolved_high_risk > new_high_risk or actionable_delta < 0 or risk_delta < 0:
        trend = "improved"
    else:
        trend = "stable"

    return {
        "trend": trend,
        "summary": {
            "current_actionable": current_summary["actionable_findings"],
            "baseline_actionable": baseline_summary["actionable_findings"],
            "actionable_delta": actionable_delta,
            "current_total_risk": current_summary["total_risk"],
            "baseline_total_risk": baseline_summary["total_risk"],
            "risk_delta": risk_delta,
            "current_max_risk": current_summary["highest_risk"],
            "baseline_max_risk": baseline_summary["highest_risk"],
            "max_risk_delta": int(current_summary["highest_risk"]) - int(baseline_summary["highest_risk"]),
            "new_actionable": len(new_entries),
            "resolved_actionable": len(resolved_entries),
            "persisting_actionable": len(persisting_keys),
            "new_high_risk": new_high_risk,
            "resolved_high_risk": resolved_high_risk,
        },
        "new_findings": new_entries,
        "resolved_findings": resolved_entries,
        "escalated_findings": escalated,
        "improved_findings": improved,
    }


def finding_identity(entry: TriageReportEntry) -> str:
    """Build a stable identity for a finding across scan runs."""
    finding = entry.finding
    location = finding.location
    parts = [
        _norm(finding.source_format),
        _norm(finding.rule_id) or _norm(finding.id),
        _norm(location.file_path),
        str(location.start_line or ""),
        str(location.end_line or ""),
        _norm(finding.cve),
        _norm(finding.cwe),
    ]
    if not any(parts):
        parts.extend([_norm(finding.title), _norm(finding.message)])
    return "|".join(parts)


def _entry_map(entries: Iterable[TriageReportEntry]) -> dict[str, TriageReportEntry]:
    result: dict[str, TriageReportEntry] = {}
    for entry in entries:
        key = finding_identity(entry)
        current = result.get(key)
        if current is None or entry.triage.risk_score > current.triage.risk_score:
            result[key] = entry
    return result


def _entry_snapshot(entry: TriageReportEntry) -> dict[str, object]:
    return {
        "finding_id": entry.finding.id,
        "rule_id": entry.finding.rule_id,
        "title": entry.finding.title,
        "file_path": entry.finding.location.file_path or "(unknown file)",
        "line": entry.finding.location.start_line,
        "risk_score": entry.triage.risk_score,
        "remediation_title": entry.remediation.title if entry.remediation else None,
    }


def _norm(value: str | None) -> str:
    return (value or "").strip().lower()
