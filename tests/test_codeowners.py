"""Tests for CODEOWNERS parsing and ownership rollups."""

from __future__ import annotations

from pathlib import Path

from vulnsift.codeowners import (
    annotate_backlog_owners,
    load_codeowners,
    owners_for_path,
    parse_codeowners,
    summarize_by_owner,
)
from vulnsift.models import Location, RemediationCard, TriageReport, TriageReportEntry, TriageResult, UnifiedFinding


def _entry(
    *,
    finding_id: str,
    rule_id: str,
    file_path: str,
    risk_score: int,
) -> TriageReportEntry:
    return TriageReportEntry(
        finding=UnifiedFinding(
            id=finding_id,
            rule_id=rule_id,
            title=rule_id,
            severity="high",
            location=Location(file_path=file_path, start_line=7),
            source_format="semgrep",
        ),
        triage=TriageResult(risk_score=risk_score, reasoning="reasoning"),
        remediation=RemediationCard(title=f"Fix {rule_id}", steps=["step one"]),
    )


def test_parse_codeowners_and_match_last_rule() -> None:
    rules = parse_codeowners(
        """
        # ownership
        src/ @platform
        src/api/ @backend
        *.md @docs
        """
    )

    assert owners_for_path("src/api/app.py", rules) == ("@backend",)
    assert owners_for_path("src/core/lib.py", rules) == ("@platform",)
    assert owners_for_path("README.md", rules) == ("@docs",)


def test_load_codeowners_finds_standard_location(tmp_path: Path) -> None:
    codeowners = tmp_path / ".github" / "CODEOWNERS"
    codeowners.parent.mkdir(parents=True)
    codeowners.write_text("src/ @platform\n", encoding="utf-8")

    rules, resolved = load_codeowners(cwd=tmp_path)

    assert resolved == codeowners
    assert len(rules) == 1


def test_summarize_by_owner_groups_findings() -> None:
    rules = parse_codeowners("src/api/ @backend\nsrc/web/ @frontend\n")
    report = TriageReport(
        source_file="report.json",
        entries=[
            _entry(finding_id="f1", rule_id="sqli", file_path="src/api/app.py", risk_score=9),
            _entry(finding_id="f2", rule_id="xss", file_path="src/web/page.py", risk_score=5),
            _entry(finding_id="f3", rule_id="deps", file_path="package.json", risk_score=4),
        ],
    )

    summary = summarize_by_owner(report, rules, unowned_label="Unowned")

    assert summary[0]["owners"] == "@backend"
    assert summary[1]["owners"] == "@frontend"
    assert summary[2]["owners"] == "Unowned"


def test_annotate_backlog_owners_adds_owner_field() -> None:
    rules = parse_codeowners("src/api/ @backend\n")
    rows = annotate_backlog_owners(
        [{"file_path": "src/api/app.py", "risk_score": 9}],
        rules,
        unowned_label="Unowned",
    )

    assert rows[0]["owners"] == "@backend"
