"""Tests for the auto-fix agent (mocked Claude API)."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import anthropic
import httpx
import pytest

from vulnsift.autofix import agent as agent_mod
from vulnsift.autofix.agent import _filter_eligible, autofix_finding, autofix_report, filter_eligible
from vulnsift.autofix.patches import MAX_SOURCE_SIZE
from vulnsift.autofix.prompts import AUTOFIX_SYSTEM_PROMPT, PatchEdit, PatchProposal
from vulnsift.llm import UsageTracker
from vulnsift.models import (
    Location,
    RemediationCard,
    TriageReport,
    TriageReportEntry,
    TriageResult,
    UnifiedFinding,
)

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "sample-triage-report.json"

VULN_LINE = 'query = "SELECT * FROM users WHERE id=" + uid'
FIXED_LINE = 'cursor.execute("SELECT * FROM users WHERE id=?", (uid,))'
SOURCE = f"import sqlite3\n\n\ndef get(cursor, uid):\n    {VULN_LINE}\n    return cursor.execute(query)\n"


def _proposal(edits=None, explanation="Use a parameterised query.", confidence=9) -> PatchProposal:
    if edits is None:
        edits = [(f"    {VULN_LINE}\n    return cursor.execute(query)", f"    return {FIXED_LINE}")]
    return PatchProposal(
        edits=[PatchEdit(old=o, new=n) for o, n in edits],
        explanation=explanation,
        confidence=confidence,
    )


def _make_entry(
    risk: int = 9,
    file_path: str = "src/app.py",
    fp: bool = False,
    finding_id: str = "test-finding-1",
    error: str | None = None,
    remediation: bool = True,
) -> TriageReportEntry:
    return TriageReportEntry(
        finding=UnifiedFinding(
            id=finding_id,
            rule_id="sql-injection",
            title="SQL Injection",
            message="SQL injection found",
            severity="high",
            description="User input concatenated into SQL.",
            cwe="CWE-89",
            location=Location(file_path=file_path, start_line=5, snippet=VULN_LINE),
            source_format="semgrep",
        ),
        triage=TriageResult(
            risk_score=risk, is_likely_false_positive=fp, reasoning="Directly exploitable.", error=error
        ),
        remediation=RemediationCard(
            title="Use parameterised queries",
            business_impact="Full database access.",
            steps=["Use parameterised query.", "Validate input."],
            code_snippet="cursor.execute('SELECT * FROM users WHERE id=?', (uid,))",
        )
        if remediation
        else None,
    )


def _write(root: Path, rel: str, content: str | bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_bytes(content.encode("utf-8"))
    return p


def _api_status_error(cls, status: int):
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    return cls(message="boom", response=httpx.Response(status, request=req), body=None)


@pytest.fixture
def mock_call():
    with patch.object(agent_mod, "structured_call") as m:
        m.return_value = _proposal()
        yield m


class TestAutofixFinding:
    def test_applies_edits_in_memory(self, mock_call):
        entry = _make_entry()
        result = autofix_finding(entry.finding, entry.triage, entry.remediation, SOURCE, client=MagicMock())
        assert result.finding_id == "test-finding-1"
        assert result.confidence == 9
        assert result.skipped_reason is None
        assert result.original_snippet == SOURCE
        assert FIXED_LINE in result.patched_snippet
        assert VULN_LINE not in result.patched_snippet
        assert result.patched_snippet.startswith("import sqlite3\n")  # rest of the file preserved
        assert f"-    {VULN_LINE}" in result.diff
        assert f"+    return {FIXED_LINE}" in result.diff
        assert result.diff.startswith("--- a/src/app.py")

    def test_prompt_wraps_untrusted_content(self, mock_call):
        entry = _make_entry()
        autofix_finding(entry.finding, entry.triage, entry.remediation, SOURCE, client=MagicMock())
        kwargs = mock_call.call_args.kwargs
        assert kwargs["system"] == AUTOFIX_SYSTEM_PROMPT
        assert kwargs["output_type"] is PatchProposal
        user = kwargs["user"]
        assert '<source_file path="src/app.py">' in user
        assert "</source_file>" in user
        assert "<finding>" in user and "</finding>" in user
        assert SOURCE in user
        assert "untrusted" in AUTOFIX_SYSTEM_PROMPT.lower()

    def test_no_edits_is_skipped(self, mock_call):
        mock_call.return_value = _proposal(edits=[], explanation="Cannot fix safely.", confidence=0)
        entry = _make_entry()
        result = autofix_finding(entry.finding, entry.triage, entry.remediation, SOURCE, client=MagicMock())
        assert result.confidence == 0
        assert result.skipped_reason == "model did not propose a fix"
        assert result.patched_snippet == ""

    def test_ambiguous_edit_rejected(self, mock_call):
        source = "x = 1\nx = 1\n"
        mock_call.return_value = _proposal(edits=[("x = 1", "x = 2")])
        entry = _make_entry()
        result = autofix_finding(entry.finding, entry.triage, entry.remediation, source, client=MagicMock())
        assert result.skipped_reason is not None
        assert "ambiguous" in result.skipped_reason
        assert result.diff == ""

    def test_missing_old_rejected(self, mock_call):
        mock_call.return_value = _proposal(edits=[("not in file", "y")])
        entry = _make_entry()
        result = autofix_finding(entry.finding, entry.triage, entry.remediation, SOURCE, client=MagicMock())
        assert "not found" in (result.skipped_reason or "")

    def test_validation_failure(self, mock_call):
        mock_call.return_value = _proposal(edits=[("def get(cursor, uid):", "def get(cursor, uid:")])
        entry = _make_entry()
        result = autofix_finding(entry.finding, entry.triage, entry.remediation, SOURCE, client=MagicMock())
        assert "validation" in (result.skipped_reason or "")
        assert result.diff  # diff still shown for review

    def test_confidence_clamped(self, mock_call):
        mock_call.return_value = _proposal(confidence=42)
        entry = _make_entry()
        result = autofix_finding(entry.finding, entry.triage, entry.remediation, SOURCE, client=MagicMock())
        assert result.confidence == 10

    def test_via_real_structured_call(self):
        """Exercise llm.structured_call with a mocked client.messages.parse."""
        client = MagicMock()
        client.messages.parse.return_value = SimpleNamespace(
            parsed_output=_proposal(),
            stop_reason="end_turn",
            usage=SimpleNamespace(input_tokens=100, output_tokens=20),
        )
        tracker = UsageTracker("claude-opus-5-5")
        entry = _make_entry()
        result = autofix_finding(
            entry.finding, entry.triage, entry.remediation, SOURCE, client=client, tracker=tracker
        )
        assert result.skipped_reason is None
        call = client.messages.parse.call_args.kwargs
        assert call["output_format"] is PatchProposal
        assert "tools" not in call and "tool_choice" not in call
        assert tracker.summary().requests == 1


class TestFilterEligible:
    def test_alias(self):
        assert _filter_eligible is filter_eligible

    def test_rules(self):
        entries = [
            _make_entry(finding_id="ok"),
            _make_entry(finding_id="low", risk=3),
            _make_entry(finding_id="fp", fp=True),
            _make_entry(finding_id="err", error="API down"),
            _make_entry(finding_id="nofile", file_path=""),
            _make_entry(finding_id="norem", remediation=False),
        ]
        assert [e.finding.id for e in filter_eligible(entries, 7.0)] == ["ok"]

    def test_from_fixture(self):
        report = TriageReport.model_validate_json(FIXTURE.read_text(encoding="utf-8"))
        ids = {e.finding.id for e in filter_eligible(report.entries, min_risk=7.0)}
        assert ids == {"finding-1", "finding-2", "finding-5"}


class TestAutofixReport:
    def test_applies_and_filters(self, mock_call, tmp_path: Path):
        src = _write(tmp_path, "src/app.py", SOURCE)
        report = TriageReport(entries=[_make_entry(), _make_entry(risk=3), _make_entry(fp=True)])
        results = autofix_report(report, tmp_path, client=MagicMock(), min_risk=7.0)
        assert len(results) == 1
        r = results[0]
        assert r.applied is True and r.skipped_reason is None
        assert r.file_path == "src/app.py"
        assert src.read_text(encoding="utf-8") == r.patched_snippet
        assert FIXED_LINE in src.read_text(encoding="utf-8")

    def test_dry_run_never_writes(self, mock_call, tmp_path: Path):
        src = _write(tmp_path, "src/app.py", SOURCE)
        before = src.stat().st_mtime_ns
        results = autofix_report(TriageReport(entries=[_make_entry()]), tmp_path, client=MagicMock(), dry_run=True)
        assert len(results) == 1
        assert results[0].applied is False
        assert results[0].skipped_reason is None
        assert results[0].diff
        assert src.read_text(encoding="utf-8") == SOURCE
        assert src.stat().st_mtime_ns == before
        assert sorted(p.name for p in src.parent.iterdir()) == ["app.py"]  # no temp files left

    def test_min_confidence(self, mock_call, tmp_path: Path):
        src = _write(tmp_path, "src/app.py", SOURCE)
        mock_call.return_value = _proposal(confidence=6)
        results = autofix_report(TriageReport(entries=[_make_entry()]), tmp_path, client=MagicMock())
        assert results[0].applied is False
        assert "min_confidence" in (results[0].skipped_reason or "")
        assert src.read_text(encoding="utf-8") == SOURCE

        results = autofix_report(TriageReport(entries=[_make_entry()]), tmp_path, client=MagicMock(), min_confidence=6)
        assert results[0].applied is True

    def test_missing_file_reported(self, mock_call, tmp_path: Path):
        results = autofix_report(TriageReport(entries=[_make_entry(file_path="nope.py")]), tmp_path, client=MagicMock())
        assert len(results) == 1
        assert "not found" in (results[0].skipped_reason or "")
        mock_call.assert_not_called()

    @pytest.mark.parametrize("bad", ["../outside.py", "src/../../outside.py"])
    def test_traversal_rejected(self, mock_call, tmp_path: Path, bad: str):
        repo = tmp_path / "repo"
        repo.mkdir()
        outside = _write(tmp_path, "outside.py", SOURCE)
        results = autofix_report(TriageReport(entries=[_make_entry(file_path=bad)]), repo, client=MagicMock())
        assert "outside the repository" in (results[0].skipped_reason or "")
        assert outside.read_text(encoding="utf-8") == SOURCE
        mock_call.assert_not_called()

    def test_absolute_path_outside_rejected(self, mock_call, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        outside = _write(tmp_path, "outside.py", SOURCE)
        results = autofix_report(TriageReport(entries=[_make_entry(file_path=str(outside))]), repo, client=MagicMock())
        assert "outside the repository" in (results[0].skipped_reason or "")
        mock_call.assert_not_called()

    def test_absolute_path_inside_allowed(self, mock_call, tmp_path: Path):
        src = _write(tmp_path, "src/app.py", SOURCE)
        results = autofix_report(TriageReport(entries=[_make_entry(file_path=str(src))]), tmp_path, client=MagicMock())
        assert results[0].applied is True
        assert results[0].file_path == "src/app.py"

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
    def test_symlink_escape_rejected(self, mock_call, tmp_path: Path):
        repo = tmp_path / "repo"
        (repo / "src").mkdir(parents=True)
        outside = _write(tmp_path, "secret.py", SOURCE)
        (repo / "src" / "app.py").symlink_to(outside)
        results = autofix_report(TriageReport(entries=[_make_entry()]), repo, client=MagicMock())
        assert "outside the repository" in (results[0].skipped_reason or "")
        assert outside.read_text(encoding="utf-8") == SOURCE

    def test_directory_rejected(self, mock_call, tmp_path: Path):
        (tmp_path / "src" / "app.py").mkdir(parents=True)
        results = autofix_report(TriageReport(entries=[_make_entry()]), tmp_path, client=MagicMock())
        assert "not a regular file" in (results[0].skipped_reason or "")

    def test_binary_and_large_files_skipped(self, mock_call, tmp_path: Path):
        _write(tmp_path, "bin.py", b"abc\0def")
        _write(tmp_path, "big.py", "x = 1\n" * (MAX_SOURCE_SIZE // 6 + 10))
        report = TriageReport(
            entries=[_make_entry(file_path="bin.py", finding_id="a"), _make_entry(file_path="big.py", finding_id="b")]
        )
        results = autofix_report(report, tmp_path, client=MagicMock())
        assert "binary" in (results[0].skipped_reason or "")
        assert "too large" in (results[1].skipped_reason or "")
        mock_call.assert_not_called()

    def test_per_finding_error_isolated(self, mock_call, tmp_path: Path):
        _write(tmp_path, "src/app.py", SOURCE)
        _write(tmp_path, "src/other.py", SOURCE)
        mock_call.side_effect = [
            _api_status_error(anthropic.InternalServerError, 500),
            _proposal(),
        ]
        report = TriageReport(
            entries=[_make_entry(finding_id="a"), _make_entry(finding_id="b", file_path="src/other.py")]
        )
        results = autofix_report(report, tmp_path, client=MagicMock())
        assert len(results) == 2
        assert results[0].applied is False
        assert "API error 500" in (results[0].skipped_reason or "")
        assert results[1].applied is True

    def test_generic_exception_isolated(self, mock_call, tmp_path: Path):
        _write(tmp_path, "src/app.py", SOURCE)
        mock_call.side_effect = ValueError("weird")
        results = autofix_report(TriageReport(entries=[_make_entry()]), tmp_path, client=MagicMock())
        assert "weird" in (results[0].skipped_reason or "")

    def test_fatal_error_reraised(self, mock_call, tmp_path: Path):
        _write(tmp_path, "src/app.py", SOURCE)
        mock_call.side_effect = _api_status_error(anthropic.AuthenticationError, 401)
        with pytest.raises(anthropic.AuthenticationError):
            autofix_report(TriageReport(entries=[_make_entry()]), tmp_path, client=MagicMock())

    def test_max_fixes_and_progress(self, mock_call, tmp_path: Path):
        _write(tmp_path, "src/app.py", SOURCE)
        seen: list[tuple[int, int, str]] = []
        report = TriageReport(entries=[_make_entry(finding_id=f"f{i}") for i in range(3)])
        results = autofix_report(
            report,
            tmp_path,
            client=MagicMock(),
            dry_run=True,
            max_fixes=2,
            on_progress=lambda done, total, r: seen.append((done, total, r.finding_id)),
        )
        assert [r.finding_id for r in results] == ["f0", "f1"]
        assert seen == [(1, 2, "f0"), (2, 2, "f1")]

    def test_no_eligible_does_not_create_client(self, tmp_path: Path):
        with patch.object(agent_mod, "make_client") as mk:
            assert autofix_report(TriageReport(entries=[_make_entry(risk=1)]), tmp_path) == []
            mk.assert_not_called()

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
    def test_preserves_mode_and_crlf(self, mock_call, tmp_path: Path):
        src = _write(tmp_path, "src/app.py", SOURCE.replace("\n", "\r\n"))
        os.chmod(src, 0o755)
        results = autofix_report(TriageReport(entries=[_make_entry()]), tmp_path, client=MagicMock())
        assert results[0].applied is True
        data = src.read_bytes()
        assert FIXED_LINE.encode() in data
        assert data.count(b"\r\n") == data.count(b"\n")  # every line ending still CRLF
        assert stat.S_IMODE(src.stat().st_mode) == 0o755
        assert "\r" not in results[0].diff

    def test_second_fix_same_file_sees_first(self, mock_call, tmp_path: Path):
        src = _write(tmp_path, "src/app.py", SOURCE)
        mock_call.side_effect = [
            _proposal(),
            _proposal(edits=[("import sqlite3\n", "import sqlite3  # patched\n")]),
        ]
        report = TriageReport(entries=[_make_entry(finding_id="a"), _make_entry(finding_id="b")])
        results = autofix_report(report, tmp_path, client=MagicMock())
        assert all(r.applied for r in results)
        text = src.read_text(encoding="utf-8")
        assert FIXED_LINE in text and "# patched" in text

    def test_json_dependency_edit_is_partial(self, mock_call, tmp_path: Path):
        """Dependency manifests are edited in place, never overwritten with only the changed line."""
        manifest = (
            '{\n  "name": "app",\n  "dependencies": {\n    "lodash": "4.17.15",\n    "express": "4.18.2"\n  }\n}\n'
        )
        pkg = _write(tmp_path, "package.json", manifest)
        mock_call.return_value = _proposal(edits=[('"lodash": "4.17.15"', '"lodash": "4.17.21"')])
        results = autofix_report(
            TriageReport(entries=[_make_entry(file_path="package.json")]), tmp_path, client=MagicMock()
        )
        assert results[0].applied is True
        text = pkg.read_text(encoding="utf-8")
        assert '"lodash": "4.17.21"' in text and '"express": "4.18.2"' in text and '"name": "app"' in text

    def test_invalid_json_rejected(self, mock_call, tmp_path: Path):
        pkg = _write(tmp_path, "package.json", '{"a": "1"}\n')
        mock_call.return_value = _proposal(edits=[('"1"}', '"1",}')])
        results = autofix_report(
            TriageReport(entries=[_make_entry(file_path="package.json")]), tmp_path, client=MagicMock()
        )
        assert "Invalid JSON" in (results[0].skipped_reason or "")
        assert pkg.read_text(encoding="utf-8") == '{"a": "1"}\n'

    def test_creates_client_when_missing(self, mock_call, tmp_path: Path):
        _write(tmp_path, "src/app.py", SOURCE)
        with patch.object(agent_mod, "make_client") as mk:
            autofix_report(TriageReport(entries=[_make_entry()]), tmp_path, dry_run=True)
            mk.assert_called_once()
        assert mock_call.call_args.args[0] is mk.return_value
