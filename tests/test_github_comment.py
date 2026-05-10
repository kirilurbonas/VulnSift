"""Tests for GitHub PR comment rendering."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from vulnsift.cli import main
from vulnsift.models import TriageReport
from vulnsift.output.github_comment import COMMENT_MARKER, render_github_comment

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "sample-triage-report.json"


def _load_report() -> TriageReport:
    return TriageReport.model_validate_json(FIXTURE.read_text(encoding="utf-8"))


class TestRenderGithubComment:
    def test_marker_present(self):
        report = _load_report()
        md = render_github_comment(report)
        assert md.startswith(COMMENT_MARKER)

    def test_summary_stats(self):
        report = _load_report()
        md = render_github_comment(report)
        assert "Findings analysed" in md
        assert "| 5 |" in md  # 5 total entries
        assert "Highest risk score" in md
        assert "Actionable findings" in md
        assert "Average actionable risk" in md

    def test_gate_passed(self):
        report = _load_report()
        md = render_github_comment(report, threshold=10.0)
        assert "PASSED" in md
        assert ":white_check_mark:" in md

    def test_gate_failed(self):
        report = _load_report()
        md = render_github_comment(report, threshold=7.0)
        assert "FAILED" in md
        assert ":x:" in md

    def test_no_threshold(self):
        report = _load_report()
        md = render_github_comment(report)
        assert "No gate threshold configured" in md

    def test_findings_table(self):
        report = _load_report()
        md = render_github_comment(report)
        assert "sql-injection" in md
        assert "hardcoded-secret" in md
        # FP finding should not appear in the table
        assert "unused-import-check" not in md

    def test_remediation_actions(self):
        report = _load_report()
        md = render_github_comment(report)
        assert "Immediate priorities" in md
        assert "Use parameterised queries" in md

    def test_hotspots_section(self):
        report = _load_report()
        md = render_github_comment(report)
        assert "Riskiest files" in md
        assert "src/db/queries.py" in md

    def test_empty_report(self):
        report = TriageReport(source_file="empty.json", entries=[])
        md = render_github_comment(report, threshold=7.0)
        assert COMMENT_MARKER in md
        assert "PASSED" in md
        assert "| 0 |" in md

    def test_vulnsift_attribution(self):
        report = _load_report()
        md = render_github_comment(report)
        assert "VulnSift" in md


class TestGithubCommentCLI:
    def test_stdout_output(self):
        runner = CliRunner()
        result = runner.invoke(main, ["github-comment", "--input", str(FIXTURE)])
        assert result.exit_code == 0
        assert COMMENT_MARKER in result.output

    def test_file_output(self, tmp_path):
        out_file = tmp_path / "comment.md"
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["github-comment", "--input", str(FIXTURE), "--output", str(out_file)],
        )
        assert result.exit_code == 0
        content = out_file.read_text(encoding="utf-8")
        assert COMMENT_MARKER in content

    def test_with_threshold(self):
        runner = CliRunner()
        result = runner.invoke(main, ["github-comment", "--input", str(FIXTURE), "--threshold", "7"])
        assert result.exit_code == 0
        assert "FAILED" in result.output
