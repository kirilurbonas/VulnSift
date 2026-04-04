"""Tests for the dashboard SQLite storage layer."""

from __future__ import annotations

import sqlite3

from vulnsift.dashboard.db import (
    get_remediation_progress,
    get_risk_trends,
    get_scan_history,
    get_top_recurring,
    init_db,
    store_report,
)
from vulnsift.models import (
    Location,
    RemediationCard,
    TriageReport,
    TriageReportEntry,
    TriageResult,
    UnifiedFinding,
)


def _in_memory_db() -> sqlite3.Connection:
    """Create an in-memory database with the schema applied."""
    return init_db(":memory:")


def _make_report(
    source: str = "scan.sarif",
    entries: list[TriageReportEntry] | None = None,
) -> TriageReport:
    if entries is None:
        entries = [
            TriageReportEntry(
                finding=UnifiedFinding(
                    id="f1",
                    rule_id="sql-injection",
                    title="SQL Injection",
                    severity="high",
                    location=Location(file_path="app.py", start_line=10),
                    source_format="semgrep",
                ),
                triage=TriageResult(risk_score=9, reasoning="Exploitable."),
                remediation=RemediationCard(title="Use parameterised queries"),
            ),
            TriageReportEntry(
                finding=UnifiedFinding(
                    id="f2",
                    rule_id="unused-import",
                    title="Unused import",
                    severity="low",
                    location=Location(file_path="utils.py"),
                    source_format="semgrep",
                ),
                triage=TriageResult(risk_score=0, is_likely_false_positive=True, reasoning="Not a vuln."),
                remediation=None,
            ),
            TriageReportEntry(
                finding=UnifiedFinding(
                    id="f3",
                    rule_id="xss",
                    title="XSS in template",
                    severity="medium",
                    cwe="CWE-79",
                    location=Location(file_path="views.py", start_line=22),
                    source_format="semgrep",
                ),
                triage=TriageResult(risk_score=5, reasoning="Reflected XSS."),
                remediation=RemediationCard(title="Escape output"),
            ),
        ]
    return TriageReport(source_file=source, entries=entries)


class TestStoreReport:
    def test_stores_and_returns_id(self):
        conn = _in_memory_db()
        scan_id = store_report(conn, _make_report())
        assert scan_id == 1

    def test_stores_findings(self):
        conn = _in_memory_db()
        store_report(conn, _make_report())
        rows = conn.execute("SELECT * FROM findings").fetchall()
        assert len(rows) == 3

    def test_scan_metadata(self):
        conn = _in_memory_db()
        store_report(conn, _make_report())
        scan = conn.execute("SELECT * FROM scans WHERE id = 1").fetchone()
        assert scan["total_findings"] == 3
        assert scan["actionable_findings"] == 2
        assert scan["max_risk"] == 9
        assert scan["false_positives"] == 1


class TestGetScanHistory:
    def test_returns_scans(self):
        conn = _in_memory_db()
        store_report(conn, _make_report("scan1.sarif"))
        store_report(conn, _make_report("scan2.sarif"))
        history = get_scan_history(conn)
        assert len(history) == 2
        # Most recent first
        assert history[0]["source_file"] == "scan2.sarif"

    def test_respects_limit(self):
        conn = _in_memory_db()
        for i in range(5):
            store_report(conn, _make_report(f"scan{i}.sarif"))
        history = get_scan_history(conn, limit=3)
        assert len(history) == 3

    def test_empty_db(self):
        conn = _in_memory_db()
        assert get_scan_history(conn) == []


class TestGetRiskTrends:
    def test_returns_trends(self):
        conn = _in_memory_db()
        store_report(conn, _make_report())
        trends = get_risk_trends(conn)
        assert len(trends) == 1
        assert trends[0]["max_risk"] == 9

    def test_multiple_scans(self):
        conn = _in_memory_db()
        store_report(conn, _make_report("a.sarif"))
        store_report(conn, _make_report("b.sarif"))
        trends = get_risk_trends(conn)
        assert len(trends) == 2


class TestGetTopRecurring:
    def test_recurring_rules(self):
        conn = _in_memory_db()
        store_report(conn, _make_report("a.sarif"))
        store_report(conn, _make_report("b.sarif"))
        recurring = get_top_recurring(conn)
        # sql-injection appears in both scans
        rule_ids = [r["rule_id"] for r in recurring]
        assert "sql-injection" in rule_ids

    def test_empty_db(self):
        conn = _in_memory_db()
        assert get_top_recurring(conn) == []


class TestGetRemediationProgress:
    def test_progress_counts(self):
        conn = _in_memory_db()
        store_report(conn, _make_report())
        progress = get_remediation_progress(conn)
        assert progress["total"] == 3
        assert progress["false_positives"] == 1
        assert progress["critical"] == 1  # risk 9
        assert progress["medium"] == 1  # risk 5
        assert progress["low"] == 0  # risk 0 is FP, not counted as low

    def test_empty_db(self):
        conn = _in_memory_db()
        progress = get_remediation_progress(conn)
        assert progress["total"] == 0
