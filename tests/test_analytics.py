"""Tests for report analytics and baseline comparison helpers."""

from __future__ import annotations

from vulnsift.analytics import compare_reports, get_hotspots, get_priority_findings, summarize_report
from vulnsift.models import Location, RemediationCard, TriageReport, TriageReportEntry, TriageResult, UnifiedFinding


def _entry(
    *,
    finding_id: str,
    rule_id: str,
    file_path: str,
    risk_score: int,
    title: str | None = None,
    start_line: int | None = None,
    is_fp: bool = False,
    remediation_title: str | None = "Fix it",
) -> TriageReportEntry:
    return TriageReportEntry(
        finding=UnifiedFinding(
            id=finding_id,
            rule_id=rule_id,
            title=title or rule_id,
            severity="high" if risk_score >= 7 else "medium",
            location=Location(file_path=file_path, start_line=start_line),
            source_format="semgrep",
        ),
        triage=TriageResult(
            risk_score=risk_score,
            is_likely_false_positive=is_fp,
            reasoning="reasoning",
        ),
        remediation=RemediationCard(title=remediation_title, steps=["step one"]) if remediation_title else None,
    )


def test_summarize_report_counts_actionable_and_fp() -> None:
    report = TriageReport(
        source_file="report.json",
        entries=[
            _entry(finding_id="f1", rule_id="sqli", file_path="app.py", risk_score=9),
            _entry(finding_id="f2", rule_id="xss", file_path="views.py", risk_score=5),
            _entry(finding_id="f3", rule_id="noise", file_path="lint.py", risk_score=0, is_fp=True),
        ],
    )

    summary = summarize_report(report)

    assert summary["total_findings"] == 3
    assert summary["actionable_findings"] == 2
    assert summary["false_positives"] == 1
    assert summary["highest_risk"] == 9
    assert summary["risk_bands"] == {"high": 1, "medium": 1, "low": 0}


def test_get_hotspots_orders_by_total_risk_then_max_risk() -> None:
    report = TriageReport(
        source_file="report.json",
        entries=[
            _entry(finding_id="f1", rule_id="sqli", file_path="app.py", risk_score=9),
            _entry(finding_id="f2", rule_id="xss", file_path="app.py", risk_score=4),
            _entry(finding_id="f3", rule_id="secret", file_path="settings.py", risk_score=8),
        ],
    )

    hotspots = get_hotspots(report, limit=2)

    assert hotspots[0]["file_path"] == "app.py"
    assert hotspots[0]["finding_count"] == 2
    assert hotspots[0]["total_risk"] == 13
    assert hotspots[1]["file_path"] == "settings.py"


def test_get_priority_findings_prefers_high_risk_with_remediation() -> None:
    report = TriageReport(
        source_file="report.json",
        entries=[
            _entry(finding_id="f1", rule_id="sqli", file_path="app.py", risk_score=9, remediation_title="Use params"),
            _entry(finding_id="f2", rule_id="xss", file_path="views.py", risk_score=9, remediation_title=None),
            _entry(finding_id="f3", rule_id="dep", file_path="package.json", risk_score=5),
        ],
    )

    priorities = get_priority_findings(report, limit=3)

    assert priorities[0]["rule_id"] == "sqli"
    assert priorities[1]["rule_id"] == "xss"
    assert priorities[2]["rule_id"] == "dep"


def test_compare_reports_tracks_new_resolved_and_escalated_findings() -> None:
    baseline = TriageReport(
        source_file="baseline.json",
        entries=[
            _entry(finding_id="f1", rule_id="sqli", file_path="app.py", risk_score=7, start_line=10),
            _entry(finding_id="f2", rule_id="xss", file_path="views.py", risk_score=4, start_line=12),
        ],
    )
    current = TriageReport(
        source_file="current.json",
        entries=[
            _entry(finding_id="f1-new", rule_id="sqli", file_path="app.py", risk_score=9, start_line=10),
            _entry(finding_id="f3", rule_id="secret", file_path="settings.py", risk_score=8, start_line=3),
        ],
    )

    comparison = compare_reports(current, baseline)

    assert comparison["trend"] == "worsened"
    assert comparison["summary"]["new_actionable"] == 1
    assert comparison["summary"]["resolved_actionable"] == 1
    assert comparison["summary"]["new_high_risk"] == 1
    assert comparison["resolved_findings"][0]["rule_id"] == "xss"
    assert comparison["new_findings"][0]["rule_id"] == "secret"
    assert comparison["escalated_findings"][0]["rule_id"] == "sqli"
    assert comparison["escalated_findings"][0]["risk_delta"] == 2
