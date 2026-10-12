"""Tests for the dashboard SQLite storage layer."""

from __future__ import annotations

import json
import sqlite3

import pytest

from vulnsift.dashboard.db import (
    DEFAULT_DB_PATH,
    SCHEMA_VERSION,
    SNIPPET_MAX_BYTES,
    delete_scan,
    get_finding,
    get_latest_hotspots,
    get_latest_priorities,
    get_overview,
    get_remediation_progress,
    get_risk_trends,
    get_scan,
    get_scan_history,
    get_top_recurring,
    init_db,
    list_projects,
    migrate,
    query_findings,
    store_report,
)
from vulnsift.models import (
    Location,
    RemediationCard,
    TriageReport,
    TriageReportEntry,
    TriageResult,
    UnifiedFinding,
    UsageSummary,
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


class TestGetOverview:
    def test_empty_db(self):
        conn = _in_memory_db()
        overview = get_overview(conn)
        assert overview["total_scans"] == 0
        assert overview["latest_scan"] is None

    def test_latest_scan_and_deltas(self):
        conn = _in_memory_db()
        store_report(conn, _make_report("scan1.sarif"))
        store_report(
            conn,
            _make_report(
                "scan2.sarif",
                entries=[
                    TriageReportEntry(
                        finding=UnifiedFinding(
                            id="f9",
                            rule_id="secret",
                            title="Hardcoded secret",
                            severity="high",
                            location=Location(file_path="settings.py", start_line=8),
                            source_format="semgrep",
                        ),
                        triage=TriageResult(risk_score=8, reasoning="Exposed."),
                        remediation=RemediationCard(title="Move secret"),
                    ),
                ],
            ),
        )

        overview = get_overview(conn)

        assert overview["total_scans"] == 2
        assert overview["latest_scan"]["source_file"] == "scan2.sarif"
        assert overview["deltas"]["actionable_findings"] == -1
        assert overview["latest_risk_bands"]["critical"] == 1


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


class TestLatestViews:
    def test_latest_hotspots(self):
        conn = _in_memory_db()
        store_report(conn, _make_report())
        hotspots = get_latest_hotspots(conn)
        assert hotspots
        assert hotspots[0]["file_path"] == "app.py"

    def test_latest_priorities(self):
        conn = _in_memory_db()
        store_report(conn, _make_report())
        priorities = get_latest_priorities(conn)
        assert priorities
        assert priorities[0]["rule_id"] == "sql-injection"


# --------------------------------------------------------------------------------------
# Schema, migrations, projects, errors, findings queries
# --------------------------------------------------------------------------------------

OLD_SCHEMA = """\
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    schema_version TEXT NOT NULL DEFAULT '1.0',
    prompt_version TEXT NOT NULL DEFAULT '1.0',
    total_findings INTEGER NOT NULL DEFAULT 0,
    actionable_findings INTEGER NOT NULL DEFAULT 0,
    max_risk INTEGER NOT NULL DEFAULT 0,
    false_positives INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    finding_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    risk_score INTEGER NOT NULL DEFAULT 0,
    is_fp INTEGER NOT NULL DEFAULT 0,
    file_path TEXT NOT NULL DEFAULT '',
    cwe TEXT,
    remediation_title TEXT
);
"""


def _entry(
    fid: str,
    rule: str,
    risk: int,
    *,
    file: str = "app.py",
    title: str | None = None,
    fp: bool = False,
    error: str | None = None,
    snippet: str | None = None,
    remediation: RemediationCard | None = None,
    confidence: int | None = None,
) -> TriageReportEntry:
    return TriageReportEntry(
        finding=UnifiedFinding(
            id=fid,
            rule_id=rule,
            title=title or rule.replace("-", " ").title(),
            severity="high",
            location=Location(file_path=file, start_line=3, end_line=5, snippet=snippet),
            source_format="sarif",
        ),
        triage=TriageResult(
            risk_score=risk, is_likely_false_positive=fp, error=error, reasoning="why", confidence=confidence
        ),
        remediation=remediation,
    )


def _create_old_db(path) -> None:
    conn = sqlite3.connect(str(path))
    conn.executescript(OLD_SCHEMA)
    conn.execute(
        "INSERT INTO scans (source_file, timestamp, total_findings, actionable_findings, max_risk, false_positives) "
        "VALUES ('old.sarif', '2025-01-01T00:00:00+00:00', 2, 1, 8, 1)"
    )
    conn.execute(
        "INSERT INTO findings (scan_id, finding_id, rule_id, title, severity, risk_score, is_fp, file_path, cwe) "
        "VALUES (1, 'o1', 'sqli', 'SQLi', 'high', 8, 0, 'a.py', 'CWE-89')"
    )
    conn.execute(
        "INSERT INTO findings (scan_id, finding_id, rule_id, title, severity, risk_score, is_fp, file_path) "
        "VALUES (1, 'o2', 'noise', 'Noise', 'low', 0, 1, 'b.py')"
    )
    # Orphan row: the old schema never enforced the FK.
    conn.execute(
        "INSERT INTO findings (scan_id, finding_id, rule_id, title, severity, risk_score, is_fp, file_path) "
        "VALUES (99, 'orphan', 'x', 'X', 'low', 1, 0, 'c.py')"
    )
    conn.commit()
    conn.close()


class TestSchema:
    def test_default_db_path(self):
        assert DEFAULT_DB_PATH.name == "dashboard.db"
        assert DEFAULT_DB_PATH.parent.name == ".vulnsift"

    def test_pragmas_and_indexes(self, tmp_path):
        conn = init_db(tmp_path / "d.db")
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        names = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
        assert {"idx_findings_scan_id", "idx_findings_rule_id", "idx_scans_project_timestamp"} <= names
        fks = conn.execute("PRAGMA foreign_key_list(findings)").fetchall()
        assert fks[0]["on_delete"] == "CASCADE"

    def test_init_is_idempotent(self, tmp_path):
        path = tmp_path / "d.db"
        init_db(path).close()
        conn = init_db(path)
        store_report(conn, _make_report())
        migrate(conn)
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3


class TestMigration:
    def test_migrates_old_schema_preserving_data(self, tmp_path):
        path = tmp_path / "old.db"
        _create_old_db(path)
        conn = init_db(path)

        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        scan_cols = {r["name"] for r in conn.execute("PRAGMA table_info(scans)")}
        assert {"project", "model", "errored_findings", "cost_usd"} <= scan_cols
        finding_cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
        assert {"is_error", "error", "reasoning", "exploitability_notes", "line", "remediation_json",
                "source_format", "confidence", "snippet"} <= finding_cols

        scan = conn.execute("SELECT * FROM scans").fetchone()
        assert scan["project"] == "default"
        assert scan["errored_findings"] == 0
        rows = conn.execute("SELECT finding_id, is_error FROM findings ORDER BY id").fetchall()
        assert [r["finding_id"] for r in rows] == ["o1", "o2"]  # orphan dropped
        assert all(r["is_error"] == 0 for r in rows)
        assert conn.execute("PRAGMA foreign_key_list(findings)").fetchone()["on_delete"] == "CASCADE"

        # Old data is queryable through the new API.
        overview = get_overview(conn)
        assert overview["latest_scan"]["source_file"] == "old.sarif"
        assert overview["latest_risk_bands"]["critical"] == 1
        assert get_finding(conn, 1)["remediation"] is None

        # New writes work and ids keep increasing after the table rebuild.
        new_id = store_report(conn, _make_report())
        assert new_id == 2
        new_rows = conn.execute("SELECT id FROM findings WHERE scan_id = 2").fetchall()
        assert min(r["id"] for r in new_rows) > 2
        conn.close()

        # Running again on the migrated DB is a no-op.
        conn = init_db(path)
        assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 2

    def test_migrates_partially_upgraded_db(self, tmp_path):
        path = tmp_path / "partial.db"
        _create_old_db(path)
        conn = sqlite3.connect(str(path))
        conn.execute("ALTER TABLE scans ADD COLUMN project TEXT NOT NULL DEFAULT 'legacy'")
        conn.commit()
        conn.close()
        conn = init_db(path)
        assert conn.execute("SELECT project FROM scans").fetchone()[0] == "legacy"
        assert "cost_usd" in {r["name"] for r in conn.execute("PRAGMA table_info(scans)")}


class TestStoreReportV2:
    def test_project_resolution(self):
        conn = _in_memory_db()
        r = _make_report()
        a = store_report(conn, r)
        r.project = "from-report"
        b = store_report(conn, r)
        c = store_report(conn, r, project="explicit")
        projects = {row["id"]: row["project"] for row in conn.execute("SELECT id, project FROM scans")}
        assert projects == {a: "default", b: "from-report", c: "explicit"}

    def test_errors_counted_separately(self):
        conn = _in_memory_db()
        report = TriageReport(
            source_file="e.sarif",
            entries=[
                _entry("a", "sqli", 9),
                _entry("b", "noise", 1, fp=True),
                _entry("c", "boom", 0, error="API timeout"),
                # Errored AND flagged FP: still an error, not an FP.
                _entry("d", "boom2", 10, fp=True, error="parse failure"),
            ],
        )
        scan_id = store_report(conn, report)
        scan = get_scan(conn, scan_id)
        assert scan["total_findings"] == 4
        assert scan["actionable_findings"] == 1
        assert scan["false_positives"] == 1
        assert scan["errored_findings"] == 2
        assert scan["max_risk"] == 9  # errored risk 10 ignored
        assert scan["risk_bands"]["errors"] == 2
        assert scan["risk_bands"]["false_positives"] == 1
        assert scan["risk_bands"]["high"] == 1
        assert scan["risk_bands"]["low"] == 0
        # Errored findings never show up as priorities / hotspots / recurring.
        assert [p["rule_id"] for p in get_latest_priorities(conn)] == ["sqli"]
        assert [r["rule_id"] for r in get_top_recurring(conn)] == ["sqli"]

    def test_metadata_and_details_stored(self):
        conn = _in_memory_db()
        card = RemediationCard(
            title="Fix", business_impact="Bad", steps=["one", "two"], code_snippet="x = 1",
            reference_links=["https://example.com"],
        )
        report = TriageReport(
            source_file="m.sarif", model="claude-x", generated_at="2026-01-01T00:00:00Z",
            usage=UsageSummary(input_tokens=10, output_tokens=5, estimated_cost_usd=0.0123),
            entries=[_entry("a", "sqli", 8, snippet="code()", remediation=card, confidence=7)],
        )
        scan_id = store_report(conn, report)
        scan = get_scan(conn, scan_id)
        assert scan["model"] == "claude-x"
        assert scan["cost_usd"] == pytest.approx(0.0123)
        assert scan["input_tokens"] == 10
        row_id = conn.execute("SELECT id FROM findings").fetchone()[0]
        detail = get_finding(conn, row_id)
        assert detail["remediation"] == json.loads(card.model_dump_json())
        assert detail["snippet"] == "code()"
        assert detail["confidence"] == 7
        assert detail["line"] == 3 and detail["end_line"] == 5
        assert detail["reasoning"] == "why"
        assert detail["status"] == "actionable" and detail["band"] == "high"
        assert detail["project"] == "default"

    def test_snippet_truncated_to_4kb(self):
        conn = _in_memory_db()
        big = "é" * 5000  # 10000 bytes in UTF-8
        store_report(conn, TriageReport(entries=[_entry("a", "r", 5, snippet=big)]))
        stored = conn.execute("SELECT snippet FROM findings").fetchone()[0]
        assert len(stored.encode("utf-8")) <= SNIPPET_MAX_BYTES
        assert stored.endswith("[truncated]")

    def test_store_is_atomic(self):
        conn = _in_memory_db()
        report = _make_report()
        conn.execute("CREATE TRIGGER boom BEFORE INSERT ON findings WHEN NEW.finding_id = 'f3' "
                     "BEGIN SELECT RAISE(ABORT, 'boom'); END")
        with pytest.raises(sqlite3.IntegrityError):
            store_report(conn, report)
        assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


class TestDeleteScan:
    def test_cascade(self):
        conn = _in_memory_db()
        a = store_report(conn, _make_report("a.sarif"))
        b = store_report(conn, _make_report("b.sarif"))
        assert delete_scan(conn, a) is True
        assert delete_scan(conn, a) is False
        assert conn.execute("SELECT COUNT(*) FROM findings WHERE scan_id = ?", (a,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM findings WHERE scan_id = ?", (b,)).fetchone()[0] == 3


class TestProjects:
    def _seed(self):
        conn = _in_memory_db()
        store_report(conn, _make_report("a1.sarif"), project="alpha")
        store_report(
            conn, TriageReport(source_file="b1.sarif", entries=[_entry("x", "secret", 8, file="s.py")]),
            project="beta",
        )
        store_report(conn, _make_report("a2.sarif"), project="alpha")
        return conn

    def test_list_projects(self):
        conn = self._seed()
        projects = list_projects(conn)
        assert [p["project"] for p in projects] == ["alpha", "beta"]
        assert projects[0]["scan_count"] == 2
        assert projects[0]["latest_scan_id"] == 3

    def test_filters(self):
        conn = self._seed()
        assert [s["source_file"] for s in get_scan_history(conn, project="beta")] == ["b1.sarif"]
        assert len(get_scan_history(conn, project="alpha")) == 2
        assert len(get_risk_trends(conn, project="alpha")) == 2
        assert [r["rule_id"] for r in get_top_recurring(conn, project="beta")] == ["secret"]
        assert get_latest_hotspots(conn, project="beta")[0]["file_path"] == "s.py"
        assert get_latest_priorities(conn, project="beta")[0]["rule_id"] == "secret"
        overview = get_overview(conn, project="beta")
        assert overview["total_scans"] == 1
        assert overview["latest_scan"]["source_file"] == "b1.sarif"
        assert overview["previous_scan"] is None
        assert get_overview(conn, project="nope")["latest_scan"] is None
        assert get_scan_history(conn, project="nope") == []

    def test_previous_scan_is_same_project(self):
        conn = self._seed()
        overview = get_overview(conn, project="alpha")
        assert overview["latest_scan"]["id"] == 3
        assert overview["previous_scan"]["id"] == 1  # not beta's scan 2

    def test_explicit_scan(self):
        conn = self._seed()
        overview = get_overview(conn, scan_id=1)
        assert overview["latest_scan"]["id"] == 1
        assert overview["previous_scan"] is None
        assert get_latest_priorities(conn, scan_id=2)[0]["rule_id"] == "secret"
        # scan/project mismatch -> nothing
        assert get_latest_priorities(conn, project="alpha", scan_id=2) == []

    def test_limit_clamped(self):
        conn = _in_memory_db()
        for i in range(3):
            store_report(conn, _make_report(f"{i}.sarif"))
        assert len(get_scan_history(conn, limit=0)) == 1
        assert len(get_scan_history(conn, limit=-5)) == 1
        assert len(get_scan_history(conn, limit=10_000)) == 3


class TestRemediationProgressDiff:
    def test_resolved_new_recurring(self):
        conn = _in_memory_db()
        store_report(conn, TriageReport(entries=[
            _entry("1", "sqli", 9, file="a.py"),
            _entry("2", "xss", 5, file="b.py"),
            _entry("3", "noise", 2, file="c.py", fp=True),
        ]))
        store_report(conn, TriageReport(entries=[
            _entry("1", "sqli", 8, file="a.py"),      # recurring
            _entry("4", "ssrf", 7, file="d.py"),      # new
            _entry("3", "noise", 4, file="c.py"),     # now actionable, but was present -> recurring
            _entry("5", "boom", 0, file="e.py", error="timeout"),  # errored: not new
        ]))
        progress = get_remediation_progress(conn)
        assert progress["previous_scan_id"] == 1
        assert progress["resolved"] == 1
        assert progress["resolved_items"][0]["rule_id"] == "xss"
        assert progress["new"] == 1
        assert progress["new_items"][0]["rule_id"] == "ssrf"
        assert progress["recurring"] == 2
        assert {i["rule_id"] for i in progress["recurring_items"]} == {"sqli", "noise"}
        assert progress["errors"] == 1
        assert progress["total"] == 4

    def test_first_scan_everything_new(self):
        conn = _in_memory_db()
        store_report(conn, _make_report())
        progress = get_remediation_progress(conn)
        assert progress["previous_scan_id"] is None
        assert progress["new"] == 2
        assert progress["resolved"] == 0

    def test_projects_not_mixed(self):
        conn = _in_memory_db()
        store_report(conn, TriageReport(entries=[_entry("1", "xss", 5)]), project="a")
        store_report(conn, TriageReport(entries=[_entry("1", "sqli", 9)]), project="b")
        progress = get_remediation_progress(conn, project="b")
        assert progress["previous_scan_id"] is None
        assert progress["resolved"] == 0


class TestQueryFindings:
    def _seed(self):
        conn = _in_memory_db()
        entries = [
            _entry("h1", "sqli", 9, file="src/db.py", title="SQL injection"),
            _entry("h2", "sqli", 7, file="src/api.py", title="SQL injection 2"),
            _entry("m1", "xss", 5, file="web/view.py", title="XSS 100%_done"),
            _entry("l1", "info", 2, file="src/util.py"),
            _entry("fp1", "noise", 6, file="test/x.py", fp=True),
            _entry("e1", "boom", 0, file="src/db.py", error="timeout"),
        ]
        scan_id = store_report(conn, TriageReport(entries=entries))
        return conn, scan_id

    def test_all_sorted_by_risk(self):
        conn, sid = self._seed()
        res = query_findings(conn, sid)
        assert res["total"] == 6
        assert [i["finding_id"] for i in res["items"]] == ["h1", "h2", "m1", "l1", "e1", "fp1"]
        assert res["items"][4]["status"] == "error" and res["items"][4]["band"] is None
        assert res["items"][5]["status"] == "fp"

    def test_status_and_band(self):
        conn, sid = self._seed()
        assert query_findings(conn, sid, status="actionable")["total"] == 4
        assert [i["finding_id"] for i in query_findings(conn, sid, status="fp")["items"]] == ["fp1"]
        assert [i["finding_id"] for i in query_findings(conn, sid, status="error")["items"]] == ["e1"]
        assert {i["finding_id"] for i in query_findings(conn, sid, band="high")["items"]} == {"h1", "h2"}
        assert [i["finding_id"] for i in query_findings(conn, sid, band="medium")["items"]] == ["m1"]
        # errored risk 0 is not "low"
        assert [i["finding_id"] for i in query_findings(conn, sid, band="low")["items"]] == ["l1"]
        assert query_findings(conn, sid, band="high", status="fp")["total"] == 0

    def test_search_rule_file(self):
        conn, sid = self._seed()
        assert query_findings(conn, sid, q="db.py")["total"] == 2
        assert query_findings(conn, sid, q="injection")["total"] == 2
        assert query_findings(conn, sid, q="100%_")["total"] == 1  # LIKE wildcards are literal
        assert query_findings(conn, sid, q="%")["total"] == 1
        assert query_findings(conn, sid, rule="sqli")["total"] == 2
        assert query_findings(conn, sid, rule="sql")["total"] == 0  # exact
        assert query_findings(conn, sid, file="src/")["total"] == 4

    def test_sort_and_pagination(self):
        conn, sid = self._seed()
        by_file = [i["file_path"] for i in query_findings(conn, sid, sort="file")["items"]]
        assert by_file == sorted(by_file)
        by_rule = [i["rule_id"] for i in query_findings(conn, sid, sort="rule")["items"]]
        assert by_rule == sorted(by_rule)
        page1 = query_findings(conn, sid, limit=2, offset=0)
        page3 = query_findings(conn, sid, limit=2, offset=4)
        assert page1["total"] == page3["total"] == 6
        assert [i["finding_id"] for i in page1["items"]] == ["h1", "h2"]
        assert [i["finding_id"] for i in page3["items"]] == ["e1", "fp1"]
        assert query_findings(conn, sid, limit=2, offset=100)["items"] == []

    def test_invalid_params(self):
        conn, sid = self._seed()
        for kwargs in ({"band": "critical"}, {"status": "bogus"}, {"sort": "id; DROP TABLE scans"}):
            with pytest.raises(ValueError):
                query_findings(conn, sid, **kwargs)

    def test_other_scan_isolated(self):
        conn, sid = self._seed()
        other = store_report(conn, _make_report())
        assert query_findings(conn, other)["total"] == 3
        assert query_findings(conn, sid)["total"] == 6
        assert get_finding(conn, 10_000) is None
