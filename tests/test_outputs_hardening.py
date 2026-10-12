"""Escaping, SARIF export, gate evaluation, identity and CODEOWNERS matching."""

from pathlib import Path

import pytest

from vulnsift.analytics import compare_reports, evaluate_gate, summarize_report
from vulnsift.codeowners import CodeownersRule, owners_for_path
from vulnsift.config import ConfigError, find_config, load_config
from vulnsift.models import Location, RemediationCard, TriageReport, TriageReportEntry, TriageResult, UnifiedFinding
from vulnsift.output.backlog import render_backlog
from vulnsift.output.github_comment import render_github_comment
from vulnsift.output.html_report import render_html_report
from vulnsift.output.sarif_export import report_to_sarif


def _entry(
    risk: int = 8,
    *,
    fp: bool = False,
    error: str | None = None,
    title: str = "SQL injection",
    path: str = "app/db.py",
    line: int | None = 10,
    snippet: str | None = None,
    rule: str = "py.sqli",
) -> TriageReportEntry:
    return TriageReportEntry(
        finding=UnifiedFinding(
            id=f"{rule}-{line}",
            rule_id=rule,
            title=title,
            severity="high",
            source_format="sarif",
            location=Location(file_path=path, start_line=line, snippet=snippet),
        ),
        triage=TriageResult(risk_score=risk, is_likely_false_positive=fp, reasoning="Because.", error=error),
        remediation=RemediationCard(title="=HYPERLINK(\"http://evil\")", steps=["Do it"]),
    )


def test_errored_entries_are_neither_actionable_nor_fp() -> None:
    report = TriageReport(entries=[_entry(), _entry(0, error="boom"), _entry(2, fp=True)])
    summary = summarize_report(report)
    assert summary["actionable_findings"] == 1
    assert summary["false_positives"] == 1
    assert summary["errored_findings"] == 1


def test_evaluate_gate() -> None:
    report = TriageReport(entries=[_entry(5), _entry(0, error="x")])
    assert evaluate_gate(report, None).passed
    assert not evaluate_gate(report, 7).passed  # error fails closed
    assert evaluate_gate(report, 7, fail_on_error=False).passed
    assert not evaluate_gate(report, 5, fail_on_error=False).passed


def test_github_comment_escapes_table_cells() -> None:
    report = TriageReport(entries=[_entry(title="a | b <script>alert(1)</script>", path="x|y.py")])
    md = render_github_comment(report, threshold=7)
    assert "<script>" not in md
    assert "a \\| b" in md
    assert "Gate: FAILED" in md
    assert "Because." in md  # reasoning is shown


def test_github_comment_lists_errors() -> None:
    md = render_github_comment(TriageReport(entries=[_entry(0, error="rate limited")]), threshold=7)
    assert "could not be triaged" in md
    assert "rate limited" in md


def test_backlog_csv_neutralises_formulas() -> None:
    csv_text = render_backlog(TriageReport(entries=[_entry()]), export_format="csv")
    assert "'=HYPERLINK" in csv_text


def test_html_report_contains_details_and_is_escaped() -> None:
    html = render_html_report(TriageReport(entries=[_entry(title="<img src=x onerror=alert(1)>")]))
    assert "<img src=x" not in html
    assert "Because." in html
    assert "prefers-color-scheme: dark" in html


def test_sarif_export_shape() -> None:
    sarif = report_to_sarif(TriageReport(entries=[_entry(9), _entry(1, fp=True, rule="other", line=3)]))
    run = sarif["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["py.sqli", "other"]
    high, fp = run["results"]
    assert high["level"] == "error"
    assert high["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    assert fp["suppressions"][0]["kind"] == "external"


def test_compare_ignores_line_moves() -> None:
    baseline = TriageReport(entries=[_entry(line=10, snippet="q = f'{x}'")])
    current = TriageReport(entries=[_entry(line=42, snippet="q  =  f'{x}'")])
    comparison = compare_reports(current, baseline)
    assert comparison["summary"]["new_actionable"] == 0
    assert comparison["summary"]["resolved_actionable"] == 0


def test_compare_counts_repeated_identities() -> None:
    baseline = TriageReport(entries=[_entry(line=1)])
    current = TriageReport(entries=[_entry(line=1), _entry(line=2)])
    assert compare_reports(current, baseline)["summary"]["new_actionable"] == 1


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        (".github/", ".github/workflows/ci.yml", True),
        ("docs", "a/docs/readme.md", True),
        ("/docs/", "a/docs/readme.md", False),
        ("*.js", "web/app.js", True),
        ("src/*.py", "src/pkg/mod.py", False),
        ("src/**/*.py", "src/pkg/mod.py", True),
        ("/build/logs/", "build/logs/x.log", True),
    ],
)
def test_codeowners_matching(pattern: str, path: str, expected: bool) -> None:
    rules = [CodeownersRule(pattern=pattern, owners=("@team",), line_number=1)]
    assert bool(owners_for_path(path, rules)) is expected


def test_config_search_and_relative_paths(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "vulnsift.yaml").write_text("output_dir: reports\nproject: shop\n")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert find_config(nested) == tmp_path / "vulnsift.yaml"
    cfg = load_config(nested)
    assert cfg.project == "shop"
    assert cfg.output_dir == str(tmp_path / "reports")


def test_config_errors_are_raised(tmp_path: Path) -> None:
    bad = tmp_path / "vulnsift.yaml"
    bad.write_text("concurrency: [1, 2\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(path=bad)
    bad.write_text("concurrency: 0\n")
    with pytest.raises(ConfigError, match="concurrency"):
        load_config(path=bad)
