"""CLI tests: validate and triage (mocked) with fixtures."""

from pathlib import Path

from click.testing import CliRunner

from vulnsift.cli import main
from vulnsift.models import Location, RemediationCard, TriageReport, TriageReportEntry, TriageResult, UnifiedFinding

runner = CliRunner()


def _report(*entries: TriageReportEntry, source_file: str = "report.json") -> TriageReport:
    return TriageReport(source_file=source_file, entries=list(entries))


def _entry(
    *,
    finding_id: str,
    rule_id: str,
    file_path: str,
    risk_score: int,
    is_fp: bool = False,
    title: str | None = None,
) -> TriageReportEntry:
    return TriageReportEntry(
        finding=UnifiedFinding(
            id=finding_id,
            rule_id=rule_id,
            title=title or rule_id,
            severity="high" if risk_score >= 7 else "medium",
            location=Location(file_path=file_path, start_line=5),
            source_format="semgrep",
        ),
        triage=TriageResult(
            risk_score=risk_score,
            is_likely_false_positive=is_fp,
            reasoning="reasoning",
        ),
        remediation=RemediationCard(title=f"Fix {rule_id}", steps=["step one"]) if not is_fp else None,
    )


def test_validate_sarif(sample_sarif_path: Path) -> None:
    result = runner.invoke(main, ["validate", "--input", str(sample_sarif_path), "--format", "sarif"])
    assert result.exit_code == 0
    assert "Parsed" in result.output
    assert "finding" in result.output.lower()


def test_validate_auto(sample_sarif_path: Path) -> None:
    result = runner.invoke(main, ["validate", "--input", str(sample_sarif_path), "--format", "auto"])
    assert result.exit_code == 0
    assert "Parsed" in result.output
    assert "sarif" in result.output.lower()


def test_validate_snyk(sample_snyk_path: Path) -> None:
    result = runner.invoke(main, ["validate", "--input", str(sample_snyk_path), "--format", "snyk"])
    assert result.exit_code == 0
    assert "Parsed" in result.output


def test_validate_missing_file() -> None:
    result = runner.invoke(main, ["validate", "--input", "/nonexistent", "--format", "sarif"])
    assert result.exit_code != 0
    assert "Error" in result.output or "failed" in result.output.lower()


def test_triage_without_key(sample_sarif_path: Path) -> None:
    import os
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    result = runner.invoke(
        main,
        ["triage", "--input", str(sample_sarif_path), "--format", "sarif"],
        env=env,
    )
    # Should fail with API key error when first triage call is made
    assert result.exit_code != 0 or "ANTHROPIC_API_KEY" in result.output or "Error" in result.output


def test_report_requires_input() -> None:
    result = runner.invoke(main, ["report"])
    assert result.exit_code != 0


def test_report_with_baseline_shows_comparison(tmp_path: Path) -> None:
    current = _report(
        _entry(finding_id="f1", rule_id="sqli", file_path="app.py", risk_score=9),
        source_file="current.json",
    )
    baseline = _report(
        _entry(finding_id="f2", rule_id="xss", file_path="views.py", risk_score=4),
        source_file="baseline.json",
    )

    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    current_path.write_text(current.model_dump_json(), encoding="utf-8")
    baseline_path.write_text(baseline.model_dump_json(), encoding="utf-8")

    result = runner.invoke(
        main,
        ["report", "--input", str(current_path), "--baseline", str(baseline_path), "--top", "3"],
    )

    assert result.exit_code == 0
    assert "Overview" in result.output
    assert "Baseline Comparison" in result.output


def test_compare_command_reports_changes(tmp_path: Path) -> None:
    current = _report(
        _entry(finding_id="f1", rule_id="sqli", file_path="app.py", risk_score=9),
        source_file="current.json",
    )
    baseline = _report(
        _entry(finding_id="f2", rule_id="xss", file_path="views.py", risk_score=4),
        source_file="baseline.json",
    )

    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    current_path.write_text(current.model_dump_json(), encoding="utf-8")
    baseline_path.write_text(baseline.model_dump_json(), encoding="utf-8")

    result = runner.invoke(
        main,
        ["compare", "--current", str(current_path), "--baseline", str(baseline_path)],
    )

    assert result.exit_code == 0
    assert "Baseline Comparison" in result.output
    assert "New Findings" in result.output
    assert "Resolved Findings" in result.output


def test_compare_command_can_fail_on_new_risk(tmp_path: Path) -> None:
    current = _report(
        _entry(finding_id="f1", rule_id="sqli", file_path="app.py", risk_score=9),
        source_file="current.json",
    )
    baseline = _report(source_file="baseline.json")

    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    current_path.write_text(current.model_dump_json(), encoding="utf-8")
    baseline_path.write_text(baseline.model_dump_json(), encoding="utf-8")

    result = runner.invoke(
        main,
        [
            "compare",
            "--current",
            str(current_path),
            "--baseline",
            str(baseline_path),
            "--fail-on-new-risk",
            "7",
        ],
    )

    assert result.exit_code == 2
    assert "Regression gate failed" in result.output


def test_share_command_writes_html_report(tmp_path: Path) -> None:
    current = _report(
        _entry(finding_id="f1", rule_id="sqli", file_path="app.py", risk_score=9),
        source_file="current.json",
    )
    baseline = _report(
        _entry(finding_id="f2", rule_id="xss", file_path="views.py", risk_score=4),
        source_file="baseline.json",
    )
    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    output_path = tmp_path / "report.html"
    current_path.write_text(current.model_dump_json(), encoding="utf-8")
    baseline_path.write_text(baseline.model_dump_json(), encoding="utf-8")

    result = runner.invoke(
        main,
        [
            "share",
            "--input",
            str(current_path),
            "--baseline",
            str(baseline_path),
            "--output",
            str(output_path),
            "--title",
            "Custom Report",
        ],
    )

    assert result.exit_code == 0
    html = output_path.read_text(encoding="utf-8")
    assert "Custom Report" in html
    assert "Baseline Comparison" in html
    assert "Priority Backlog" in html


def test_backlog_command_writes_csv(tmp_path: Path) -> None:
    report = _report(
        _entry(finding_id="f1", rule_id="sqli", file_path="app.py", risk_score=9),
        _entry(finding_id="f2", rule_id="xss", file_path="views.py", risk_score=5),
        source_file="report.json",
    )
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "backlog.csv"
    report_path.write_text(report.model_dump_json(), encoding="utf-8")

    result = runner.invoke(
        main,
        [
            "backlog",
            "--input",
            str(report_path),
            "--format",
            "csv",
            "--output",
            str(output_path),
            "--top",
            "10",
        ],
    )

    assert result.exit_code == 0
    content = output_path.read_text(encoding="utf-8")
    assert "risk_score" in content
    assert "sqli" in content


def test_backlog_command_markdown_stdout(tmp_path: Path) -> None:
    report = _report(
        _entry(finding_id="f1", rule_id="sqli", file_path="app.py", risk_score=9),
        source_file="report.json",
    )
    report_path = tmp_path / "report.json"
    report_path.write_text(report.model_dump_json(), encoding="utf-8")

    result = runner.invoke(
        main,
        [
            "backlog",
            "--input",
            str(report_path),
            "--format",
            "md",
            "--top",
            "5",
        ],
    )

    assert result.exit_code == 0
    assert "prioritized backlog" in result.output.lower()
    assert "sqli" in result.output


def test_version() -> None:
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.2.0" in result.output


def test_triage_dry_run(sample_sarif_path: Path) -> None:
    result = runner.invoke(
        main,
        ["triage", "--input", str(sample_sarif_path), "--format", "sarif", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Dry run" in result.output
    assert "Would triage" in result.output


def test_triage_gate_threshold_dry_run(sample_sarif_path: Path) -> None:
    # In dry-run mode, gate-threshold should not cause a non-zero exit; no triage is performed.
    result = runner.invoke(
        main,
        [
            "triage",
            "--input",
            str(sample_sarif_path),
            "--format",
            "sarif",
            "--dry-run",
            "--gate-threshold",
            "1",
        ],
    )
    assert result.exit_code == 0


def test_triage_limit(sample_sarif_path: Path) -> None:
    result = runner.invoke(
        main,
        ["triage", "--input", str(sample_sarif_path), "--format", "sarif", "--limit", "1", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Would triage" in result.output


def test_triage_sample_dry_run(sample_sarif_path: Path) -> None:
    result = runner.invoke(
        main,
        ["triage", "--input", str(sample_sarif_path), "--format", "sarif", "--sample", "1", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Would triage" in result.output


def test_triage_seed_sample_dry_run(sample_sarif_path: Path) -> None:
    result = runner.invoke(
        main,
        [
            "triage",
            "--input",
            str(sample_sarif_path),
            "--format",
            "sarif",
            "--sample",
            "1",
            "--seed",
            "42",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "Would triage" in result.output
