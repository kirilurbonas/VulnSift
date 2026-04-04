"""Tests for the auto-fix agent (mocked Claude API)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from vulnsift.autofix.agent import autofix_finding, autofix_report
from vulnsift.models import (
    AutofixResult,
    Location,
    RemediationCard,
    TriageReport,
    TriageReportEntry,
    TriageResult,
    UnifiedFinding,
)

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "sample-triage-report.json"


def _mock_response(patched_code: str, explanation: str, confidence: int):
    """Create a mock Claude API response with submit_patch tool use."""
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.name = "submit_patch"
    tool_block.input = {
        "patched_code": patched_code,
        "explanation": explanation,
        "confidence": confidence,
    }
    response = MagicMock()
    response.content = [tool_block]
    return response


def _make_entry(risk: int = 9, file_path: str = "src/app.py", fp: bool = False) -> TriageReportEntry:
    return TriageReportEntry(
        finding=UnifiedFinding(
            id="test-finding-1",
            rule_id="sql-injection",
            title="SQL Injection",
            message="SQL injection found",
            severity="high",
            description="User input concatenated into SQL.",
            cwe="CWE-89",
            location=Location(
                file_path=file_path,
                start_line=10,
                snippet='query = "SELECT * FROM users WHERE id=" + uid',
            ),
            source_format="semgrep",
        ),
        triage=TriageResult(
            risk_score=risk,
            is_likely_false_positive=fp,
            reasoning="Directly exploitable.",
        ),
        remediation=RemediationCard(
            title="Use parameterised queries",
            business_impact="Full database access.",
            steps=["Use parameterised query.", "Validate input."],
            code_snippet="cursor.execute('SELECT * FROM users WHERE id=?', (uid,))",
        ),
    )


class TestAutofixFinding:
    @patch("vulnsift.autofix.agent.Anthropic")
    def test_returns_autofix_result(self, mock_cls):
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.messages.create.return_value = _mock_response(
            patched_code='cursor.execute("SELECT * FROM users WHERE id=?", (uid,))',
            explanation="Replaced string concat with parameterised query.",
            confidence=9,
        )

        entry = _make_entry()
        result = autofix_finding(
            entry.finding,
            entry.triage,
            entry.remediation,
            'query = "SELECT * FROM users WHERE id=" + uid',
            api_key="test-key",
        )

        assert isinstance(result, AutofixResult)
        assert result.finding_id == "test-finding-1"
        assert result.confidence == 9
        assert "parameterised" in result.explanation.lower()

    @patch("vulnsift.autofix.agent.Anthropic")
    def test_low_confidence_on_failure(self, mock_cls):
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.messages.create.return_value = _mock_response(
            patched_code="",
            explanation="Cannot fix safely.",
            confidence=0,
        )

        entry = _make_entry()
        result = autofix_finding(
            entry.finding,
            entry.triage,
            entry.remediation,
            'query = "SELECT * FROM users WHERE id=" + uid',
            api_key="test-key",
        )

        assert result.confidence == 0


class TestAutofixReport:
    @patch("vulnsift.autofix.agent.Anthropic")
    def test_filters_by_risk(self, mock_cls, tmp_path: Path):
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.messages.create.return_value = _mock_response(
            patched_code="fixed code",
            explanation="Fixed.",
            confidence=8,
        )

        # Create a source file
        src = tmp_path / "src" / "app.py"
        src.parent.mkdir(parents=True)
        src.write_text('query = "SELECT * FROM users WHERE id=" + uid\n', encoding="utf-8")

        high_risk = _make_entry(risk=9, file_path="src/app.py")
        low_risk = _make_entry(risk=3, file_path="src/app.py")
        fp_entry = _make_entry(risk=9, file_path="src/app.py", fp=True)

        report = TriageReport(entries=[high_risk, low_risk, fp_entry], source_file="test.json")
        results = autofix_report(report, tmp_path, dry_run=True, min_risk=7.0, api_key="test-key")

        # Only the high-risk non-FP entry should be processed
        assert len(results) == 1
        assert results[0].finding_id == "test-finding-1"

    @patch("vulnsift.autofix.agent.Anthropic")
    def test_skips_missing_files(self, mock_cls, tmp_path: Path):
        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        entry = _make_entry(risk=9, file_path="nonexistent.py")
        report = TriageReport(entries=[entry], source_file="test.json")
        results = autofix_report(report, tmp_path, dry_run=True, min_risk=7.0, api_key="test-key")

        assert len(results) == 0
        mock_client.messages.create.assert_not_called()

    def test_from_fixture(self, tmp_path: Path):
        """Verify the fixture loads and filtering works without API calls."""
        report = TriageReport.model_validate_json(FIXTURE.read_text(encoding="utf-8"))
        from vulnsift.autofix.agent import _filter_eligible

        eligible = _filter_eligible(report.entries, min_risk=7.0)
        # finding-1 (risk 9), finding-2 (risk 7), finding-5 (risk 8) are eligible
        assert len(eligible) == 3
        ids = {e.finding.id for e in eligible}
        assert "finding-1" in ids
        assert "finding-5" in ids
