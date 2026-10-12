"""SQLite storage for scan history and dashboard queries.

Connections returned by :func:`connect` / :func:`init_db` run in autocommit mode
(``isolation_level=None``); writes are wrapped in explicit transactions here.
Every connection enables ``foreign_keys`` and (for file databases) WAL mode so
that the threaded dashboard server can read while the CLI writes.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnsift.models import (
    HIGH_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD,
    TriageReport,
    TriageReportEntry,
    max_actionable_risk,
    risk_band,
)

DEFAULT_DB_PATH = Path.home() / ".vulnsift" / "dashboard.db"
DEFAULT_PROJECT = "default"
SCHEMA_VERSION = 2
SNIPPET_MAX_BYTES = 4096
MAX_PAGE_SIZE = 500

_TRUNCATION_MARKER = "\n... [truncated]"

# --------------------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------------------

# Column name -> declaration used both for CREATE TABLE and for ALTER TABLE ADD COLUMN
# migrations. Every column added after v1 must be ADD-able (nullable or with a default).
SCAN_COLUMNS: dict[str, str] = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "source_file": "TEXT NOT NULL",
    "timestamp": "TEXT NOT NULL",
    "schema_version": "TEXT NOT NULL DEFAULT '1.0'",
    "prompt_version": "TEXT NOT NULL DEFAULT '1.0'",
    "total_findings": "INTEGER NOT NULL DEFAULT 0",
    "actionable_findings": "INTEGER NOT NULL DEFAULT 0",
    "max_risk": "INTEGER NOT NULL DEFAULT 0",
    "false_positives": "INTEGER NOT NULL DEFAULT 0",
    # v2
    "project": f"TEXT NOT NULL DEFAULT '{DEFAULT_PROJECT}'",
    "model": "TEXT",
    "errored_findings": "INTEGER NOT NULL DEFAULT 0",
    "cost_usd": "REAL",
    "generated_at": "TEXT",
    "input_tokens": "INTEGER",
    "output_tokens": "INTEGER",
}

FINDING_COLUMNS: dict[str, str] = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "scan_id": "INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE",
    "finding_id": "TEXT NOT NULL",
    "rule_id": "TEXT NOT NULL",
    "title": "TEXT NOT NULL DEFAULT ''",
    "severity": "TEXT NOT NULL DEFAULT ''",
    "risk_score": "INTEGER NOT NULL DEFAULT 0",
    "is_fp": "INTEGER NOT NULL DEFAULT 0",
    "file_path": "TEXT NOT NULL DEFAULT ''",
    "cwe": "TEXT",
    "remediation_title": "TEXT",
    # v2
    "is_error": "INTEGER NOT NULL DEFAULT 0",
    "error": "TEXT",
    "reasoning": "TEXT",
    "exploitability_notes": "TEXT",
    "confidence": "INTEGER",
    "line": "INTEGER",
    "end_line": "INTEGER",
    "cve": "TEXT",
    "message": "TEXT",
    "description": "TEXT",
    "source_format": "TEXT",
    "snippet": "TEXT",
    "remediation_json": "TEXT",
}

INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id)",
    "CREATE INDEX IF NOT EXISTS idx_scans_project_timestamp ON scans(project, timestamp)",
)


def _create_table_sql(name: str, columns: dict[str, str], *, if_not_exists: bool = True) -> str:
    cols = ",\n    ".join(f"{col} {decl}" for col, decl in columns.items())
    guard = "IF NOT EXISTS " if if_not_exists else ""
    return f"CREATE TABLE {guard}{name} (\n    {cols}\n)"


# --------------------------------------------------------------------------------------
# Connections, transactions, migrations
# --------------------------------------------------------------------------------------


def connect(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a connection with the dashboard's pragmas. Does not create or migrate the schema."""
    db_path = str(db_path)
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    if db_path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
    """Run a block atomically. Nests safely (uses a SAVEPOINT when already in a transaction)."""
    if conn.in_transaction:
        conn.execute("SAVEPOINT vulnsift_tx")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK TO SAVEPOINT vulnsift_tx")
            conn.execute("RELEASE SAVEPOINT vulnsift_tx")
            raise
        conn.execute("RELEASE SAVEPOINT vulnsift_tx")
        return
    conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def _findings_fk_cascades(conn: sqlite3.Connection) -> bool:
    for row in conn.execute("PRAGMA foreign_key_list(findings)"):
        if row["table"] == "scans" and str(row["on_delete"]).upper() == "CASCADE":
            return True
    return False


def migrate(conn: sqlite3.Connection) -> None:
    """Create or upgrade the schema in place. Idempotent and safe to run on every start.

    v0/v1 (pre-versioned) databases get the missing columns via ``ALTER TABLE ADD COLUMN``;
    the ``findings`` table is rebuilt once so its foreign key gains ``ON DELETE CASCADE``
    (SQLite cannot alter constraints in place). Data is preserved.
    """
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version >= SCHEMA_VERSION and _table_columns(conn, "findings"):
        return

    # Foreign keys must be off while the findings table is rebuilt; the pragma is a
    # no-op inside a transaction, so toggle it outside.
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        with transaction(conn, immediate=True):
            conn.execute(_create_table_sql("scans", SCAN_COLUMNS))
            conn.execute(_create_table_sql("findings", FINDING_COLUMNS))

            for table, columns in (("scans", SCAN_COLUMNS), ("findings", FINDING_COLUMNS)):
                existing = _table_columns(conn, table)
                for col, decl in columns.items():
                    if col not in existing:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")

            if not _findings_fk_cascades(conn):
                cols = ", ".join(FINDING_COLUMNS)
                conn.execute(_create_table_sql("findings_v2", FINDING_COLUMNS, if_not_exists=False))
                # Drop orphans: the old schema never enforced the foreign key.
                conn.execute(
                    f"INSERT INTO findings_v2 ({cols}) SELECT {cols} FROM findings "
                    "WHERE scan_id IN (SELECT id FROM scans)"
                )
                conn.execute("DROP TABLE findings")
                conn.execute("ALTER TABLE findings_v2 RENAME TO findings")

            for stmt in INDEXES:
                conn.execute(stmt)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    finally:
        conn.execute("PRAGMA foreign_keys = ON")


def init_db(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open (creating/migrating if needed) the dashboard database and return a connection."""
    conn = connect(db_path)
    migrate(conn)
    return conn


# --------------------------------------------------------------------------------------
# Writes
# --------------------------------------------------------------------------------------


def _truncate_snippet(snippet: str | None) -> str | None:
    if not snippet:
        return snippet
    raw = snippet.encode("utf-8")
    if len(raw) <= SNIPPET_MAX_BYTES:
        return snippet
    budget = SNIPPET_MAX_BYTES - len(_TRUNCATION_MARKER.encode("utf-8"))
    return raw[:budget].decode("utf-8", errors="ignore") + _TRUNCATION_MARKER


def _finding_row(scan_id: int, entry: TriageReportEntry) -> tuple:
    f = entry.finding
    t = entry.triage
    return (
        scan_id,
        f.id,
        f.rule_id,
        f.title,
        f.severity,
        t.risk_score,
        int(entry.is_false_positive),
        f.location.file_path,
        f.cwe,
        entry.remediation.title if entry.remediation else None,
        int(t.is_error),
        t.error,
        t.reasoning,
        t.exploitability_notes,
        t.confidence,
        f.location.start_line,
        f.location.end_line,
        f.cve,
        f.message,
        f.description,
        f.source_format,
        _truncate_snippet(f.location.snippet),
        entry.remediation.model_dump_json() if entry.remediation else None,
    )


_FINDING_INSERT_COLS = (
    "scan_id, finding_id, rule_id, title, severity, risk_score, is_fp, file_path, cwe, remediation_title, "
    "is_error, error, reasoning, exploitability_notes, confidence, line, end_line, cve, message, description, "
    "source_format, snippet, remediation_json"
)


def store_report(conn: sqlite3.Connection, report: TriageReport, *, project: str | None = None) -> int:
    """Store a triage report atomically and return the new scan ID.

    ``project`` falls back to ``report.project`` and then ``'default'``. Errored entries
    (triage failed) are counted in ``errored_findings`` and are neither actionable nor FPs.
    """
    project = (project or report.project or DEFAULT_PROJECT).strip() or DEFAULT_PROJECT
    entries = report.entries
    actionable = sum(1 for e in entries if e.is_actionable)
    fps = sum(1 for e in entries if e.is_false_positive)
    errored = sum(1 for e in entries if e.triage.is_error)
    usage = report.usage

    with transaction(conn, immediate=True):
        cursor = conn.execute(
            """INSERT INTO scans (source_file, timestamp, schema_version, prompt_version,
               total_findings, actionable_findings, max_risk, false_positives,
               project, model, errored_findings, cost_usd, generated_at, input_tokens, output_tokens)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report.source_file,
                datetime.now(UTC).isoformat(),
                report.schema_version,
                report.prompt_version,
                len(entries),
                actionable,
                max_actionable_risk(entries),
                fps,
                project,
                report.model or None,
                errored,
                usage.estimated_cost_usd if usage else None,
                report.generated_at or None,
                usage.input_tokens if usage else None,
                usage.output_tokens if usage else None,
            ),
        )
        scan_id = int(cursor.lastrowid)
        placeholders = ", ".join("?" * len(_FINDING_INSERT_COLS.split(",")))
        conn.executemany(
            f"INSERT INTO findings ({_FINDING_INSERT_COLS}) VALUES ({placeholders})",
            [_finding_row(scan_id, e) for e in entries],
        )
    return scan_id


def delete_scan(conn: sqlite3.Connection, scan_id: int) -> bool:
    """Delete a scan and (via ON DELETE CASCADE) its findings. Returns False if it did not exist."""
    with transaction(conn, immediate=True):
        cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return cursor.rowcount > 0


# --------------------------------------------------------------------------------------
# Query helpers
# --------------------------------------------------------------------------------------

ACTIONABLE_SQL = "is_fp = 0 AND is_error = 0"
_H = int(HIGH_RISK_THRESHOLD)
_M = int(MEDIUM_RISK_THRESHOLD)
BAND_SQL = {
    "high": f"risk_score >= {_H}",
    "medium": f"risk_score >= {_M} AND risk_score < {_H}",
    "low": f"risk_score < {_M}",
}
STATUS_SQL = {
    "actionable": ACTIONABLE_SQL,
    "fp": "is_fp = 1 AND is_error = 0",
    "error": "is_error = 1",
}

_BAND_COUNTS_SQL = f"""SELECT
    COUNT(*) AS total,
    COALESCE(SUM(CASE WHEN {ACTIONABLE_SQL} AND {BAND_SQL["high"]} THEN 1 ELSE 0 END), 0) AS high,
    COALESCE(SUM(CASE WHEN {ACTIONABLE_SQL} AND {BAND_SQL["medium"]} THEN 1 ELSE 0 END), 0) AS medium,
    COALESCE(SUM(CASE WHEN {ACTIONABLE_SQL} AND {BAND_SQL["low"]} THEN 1 ELSE 0 END), 0) AS low,
    COALESCE(SUM(CASE WHEN {STATUS_SQL["fp"]} THEN 1 ELSE 0 END), 0) AS false_positives,
    COALESCE(SUM(CASE WHEN is_error = 1 THEN 1 ELSE 0 END), 0) AS errors
  FROM findings WHERE scan_id = ?"""


def _clamp(value: int, lo: int = 1, hi: int = MAX_PAGE_SIZE) -> int:
    return max(lo, min(hi, int(value)))


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _band_counts(conn: sqlite3.Connection, scan_id: int) -> dict[str, int]:
    row = conn.execute(_BAND_COUNTS_SQL, (scan_id,)).fetchone()
    counts = {k: int(row[k]) for k in row.keys()}
    counts["critical"] = counts["high"]  # backward-compatible alias
    return counts


def _resolve_scan(
    conn: sqlite3.Connection, project: str | None = None, scan_id: int | None = None
) -> sqlite3.Row | None:
    """The explicit scan (optionally checked against project), else the latest scan of project/overall."""
    if scan_id is not None:
        sql, params = "SELECT * FROM scans WHERE id = ?", [scan_id]
        if project is not None:
            sql += " AND project = ?"
            params.append(project)
        return conn.execute(sql, params).fetchone()
    if project is not None:
        return conn.execute(
            "SELECT * FROM scans WHERE project = ? ORDER BY timestamp DESC, id DESC LIMIT 1", (project,)
        ).fetchone()
    return conn.execute("SELECT * FROM scans ORDER BY timestamp DESC, id DESC LIMIT 1").fetchone()


def _previous_scan(conn: sqlite3.Connection, scan: sqlite3.Row) -> sqlite3.Row | None:
    """The scan stored immediately before ``scan`` in the same project."""
    return conn.execute(
        """SELECT * FROM scans WHERE project = ? AND (timestamp < ? OR (timestamp = ? AND id < ?))
           ORDER BY timestamp DESC, id DESC LIMIT 1""",
        (scan["project"], scan["timestamp"], scan["timestamp"], scan["id"]),
    ).fetchone()


def _status(row: sqlite3.Row | dict) -> str:
    if row["is_error"]:
        return "error"
    if row["is_fp"]:
        return "fp"
    return "actionable"


def _decorate_finding(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["status"] = _status(row)
    d["band"] = risk_band(row["risk_score"]) if d["status"] == "actionable" else None
    d["is_fp"] = bool(d["is_fp"])
    d["is_error"] = bool(d["is_error"])
    return d


# --------------------------------------------------------------------------------------
# Queries
# --------------------------------------------------------------------------------------


def list_projects(conn: sqlite3.Connection) -> list[dict]:
    """Projects with their scan count and latest scan (most recently scanned first)."""
    rows = conn.execute(
        """SELECT s.project, c.scan_count, s.id AS latest_scan_id, s.timestamp AS latest_timestamp,
                  s.max_risk AS latest_max_risk, s.actionable_findings AS latest_actionable
           FROM (SELECT project, COUNT(*) AS scan_count,
                        (SELECT id FROM scans s2 WHERE s2.project = s1.project
                         ORDER BY timestamp DESC, id DESC LIMIT 1) AS latest_id
                 FROM scans s1 GROUP BY project) c
           JOIN scans s ON s.id = c.latest_id
           ORDER BY s.timestamp DESC, s.id DESC"""
    ).fetchall()
    return [dict(r) for r in rows]


def get_scan_history(
    conn: sqlite3.Connection, limit: int = 50, *, project: str | None = None, offset: int = 0
) -> list[dict]:
    """Return recent scans ordered by timestamp descending."""
    sql = "SELECT * FROM scans"
    params: list[Any] = []
    if project is not None:
        sql += " WHERE project = ?"
        params.append(project)
    sql += " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
    params += [_clamp(limit), max(0, int(offset))]
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_scan(conn: sqlite3.Connection, scan_id: int) -> dict | None:
    """One scan with its risk-band counts and the id of the previous scan in its project."""
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    scan = dict(row)
    scan["risk_bands"] = _band_counts(conn, scan_id)
    prev = _previous_scan(conn, row)
    scan["previous_scan_id"] = prev["id"] if prev else None
    return scan


def get_risk_trends(conn: sqlite3.Connection, last_n: int = 20, *, project: str | None = None) -> list[dict]:
    """Per-scan max/avg actionable risk and band counts for the last N scans (oldest first)."""
    where, params = "", []
    if project is not None:
        where, params = "WHERE s.project = ?", [project]
    rows = conn.execute(
        f"""SELECT s.id, s.timestamp, s.project, s.source_file, s.max_risk,
                  ROUND(AVG(f.risk_score), 1) AS avg_risk,
                  COUNT(f.id) AS finding_count,
                  COALESCE(SUM(CASE WHEN f.{BAND_SQL["high"]} THEN 1 ELSE 0 END), 0) AS high,
                  COALESCE(SUM(CASE WHEN f.risk_score >= {_M} AND f.risk_score < {_H} THEN 1 ELSE 0 END), 0)
                      AS medium,
                  COALESCE(SUM(CASE WHEN f.{BAND_SQL["low"]} THEN 1 ELSE 0 END), 0) AS low,
                  s.false_positives, s.errored_findings
           FROM scans s
           LEFT JOIN findings f ON f.scan_id = s.id AND f.is_fp = 0 AND f.is_error = 0
           {where}
           GROUP BY s.id
           ORDER BY s.timestamp DESC, s.id DESC
           LIMIT ?""",
        (*params, _clamp(last_n)),
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


_EMPTY_DELTAS = {
    "total_findings": 0,
    "actionable_findings": 0,
    "max_risk": 0,
    "false_positives": 0,
    "errored_findings": 0,
    "critical_findings": 0,
}


def get_overview(conn: sqlite3.Connection, *, project: str | None = None, scan_id: int | None = None) -> dict:
    """Selected (default: latest) scan overview plus deltas from the previous scan of the same project."""
    total_sql, total_params = "SELECT COUNT(*) FROM scans", []
    if project is not None:
        total_sql, total_params = total_sql + " WHERE project = ?", [project]
    total_scans = conn.execute(total_sql, total_params).fetchone()[0]

    scan = _resolve_scan(conn, project, scan_id)
    if scan is None:
        return {
            "total_scans": total_scans,
            "project": project,
            "latest_scan": None,
            "previous_scan": None,
            "deltas": dict(_EMPTY_DELTAS),
            "latest_risk_bands": {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "false_positives": 0, "errors": 0, "total": 0,
            },
        }

    previous = _previous_scan(conn, scan)
    latest = dict(scan)
    prev = dict(previous) if previous else None
    bands = _band_counts(conn, latest["id"])
    prev_high = _band_counts(conn, prev["id"])["high"] if prev else 0

    def delta(key: str) -> int:
        return (latest[key] or 0) - ((prev[key] or 0) if prev else 0)

    deltas = {key: delta(key) for key in _EMPTY_DELTAS if key != "critical_findings"}
    deltas["critical_findings"] = bands["high"] - prev_high
    return {
        "total_scans": total_scans,
        "project": latest["project"],
        "latest_scan": latest,
        "previous_scan": prev,
        "deltas": deltas,
        "latest_risk_bands": bands,
    }


def get_top_recurring(conn: sqlite3.Connection, limit: int = 10, *, project: str | None = None) -> list[dict]:
    """Most frequently occurring actionable rule_ids across scans."""
    join, params = "", []
    if project is not None:
        join, params = "JOIN scans s ON s.id = f.scan_id AND s.project = ?", [project]
    rows = conn.execute(
        f"""SELECT f.rule_id, MAX(f.title) AS title, COUNT(*) AS occurrences,
                  MAX(f.risk_score) AS max_risk,
                  COUNT(DISTINCT f.scan_id) AS scan_count
           FROM findings f {join}
           WHERE f.is_fp = 0 AND f.is_error = 0
           GROUP BY f.rule_id
           ORDER BY occurrences DESC, max_risk DESC, f.rule_id ASC
           LIMIT ?""",
        (*params, _clamp(limit)),
    ).fetchall()
    return [dict(r) for r in rows]


def get_latest_hotspots(
    conn: sqlite3.Connection, limit: int = 8, *, project: str | None = None, scan_id: int | None = None
) -> list[dict]:
    """Riskiest files (actionable findings only) in the selected/latest scan."""
    scan = _resolve_scan(conn, project, scan_id)
    if scan is None:
        return []
    rows = conn.execute(
        f"""SELECT
             file_path,
             COUNT(*) AS finding_count,
             SUM(CASE WHEN {BAND_SQL["high"]} THEN 1 ELSE 0 END) AS high_risk_count,
             MAX(risk_score) AS max_risk,
             ROUND(AVG(risk_score), 1) AS avg_risk,
             SUM(risk_score) AS total_risk
           FROM findings
           WHERE scan_id = ? AND {ACTIONABLE_SQL}
           GROUP BY file_path
           ORDER BY total_risk DESC, max_risk DESC, finding_count DESC, file_path ASC
           LIMIT ?""",
        (scan["id"], _clamp(limit)),
    ).fetchall()
    return [dict(r) for r in rows]


def get_latest_priorities(
    conn: sqlite3.Connection, limit: int = 8, *, project: str | None = None, scan_id: int | None = None
) -> list[dict]:
    """Highest-risk actionable findings in the selected/latest scan."""
    scan = _resolve_scan(conn, project, scan_id)
    if scan is None:
        return []
    rows = conn.execute(
        f"""SELECT id, finding_id, rule_id, title, risk_score, file_path, line, confidence, remediation_title
           FROM findings
           WHERE scan_id = ? AND {ACTIONABLE_SQL}
           ORDER BY risk_score DESC, file_path ASC, rule_id ASC
           LIMIT ?""",
        (scan["id"], _clamp(limit)),
    ).fetchall()
    return [dict(r) for r in rows]


def _identity(row: sqlite3.Row) -> tuple[str, str, str]:
    return (row["rule_id"], row["file_path"], row["title"])


def get_remediation_progress(
    conn: sqlite3.Connection,
    *,
    project: str | None = None,
    scan_id: int | None = None,
    item_limit: int = 20,
) -> dict:
    """Compare the selected/latest scan with the previous scan of the same project.

    Findings are matched on identity ``(rule_id, file_path, title)``:

    * ``resolved``  – actionable in the previous scan, absent from this scan entirely;
    * ``new``       – actionable in this scan, absent from the previous scan;
    * ``recurring`` – actionable in this scan and present in the previous scan.

    Also returns this scan's band counts (``total``, ``false_positives``, ``errors``,
    ``critical``/``high``, ``medium``, ``low``). With no previous scan, everything actionable is new.
    """
    scan = _resolve_scan(conn, project, scan_id)
    empty_bands = {"total": 0, "false_positives": 0, "errors": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    if scan is None:
        return {
            "scan_id": None, "previous_scan_id": None, "resolved": 0, "new": 0, "recurring": 0,
            "resolved_items": [], "new_items": [], "recurring_items": [], **empty_bands,
        }
    previous = _previous_scan(conn, scan)

    cols = "rule_id, file_path, title, risk_score, is_fp, is_error"
    current_rows = conn.execute(f"SELECT {cols} FROM findings WHERE scan_id = ?", (scan["id"],)).fetchall()
    prev_rows = (
        conn.execute(f"SELECT {cols} FROM findings WHERE scan_id = ?", (previous["id"],)).fetchall()
        if previous
        else []
    )

    def actionable_map(rows: list[sqlite3.Row]) -> dict[tuple, int]:
        out: dict[tuple, int] = {}
        for r in rows:
            if not r["is_fp"] and not r["is_error"]:
                key = _identity(r)
                out[key] = max(out.get(key, 0), r["risk_score"])
        return out

    current_all = {_identity(r) for r in current_rows}
    prev_all = {_identity(r) for r in prev_rows}
    current_act = actionable_map(current_rows)
    prev_act = actionable_map(prev_rows)

    resolved = {k: v for k, v in prev_act.items() if k not in current_all}
    new = {k: v for k, v in current_act.items() if k not in prev_all}
    recurring = {k: v for k, v in current_act.items() if k in prev_all}

    def items(group: dict[tuple, int]) -> list[dict]:
        ordered = sorted(group.items(), key=lambda kv: (-kv[1], kv[0]))[: _clamp(item_limit)]
        return [{"rule_id": r, "file_path": f, "title": t, "risk_score": s} for (r, f, t), s in ordered]

    return {
        "scan_id": scan["id"],
        "previous_scan_id": previous["id"] if previous else None,
        "resolved": len(resolved),
        "new": len(new),
        "recurring": len(recurring),
        "resolved_items": items(resolved),
        "new_items": items(new),
        "recurring_items": items(recurring),
        **_band_counts(conn, scan["id"]),
    }


FINDING_SORTS = {
    "risk": f"CASE WHEN {ACTIONABLE_SQL} THEN 0 WHEN is_error = 1 THEN 1 ELSE 2 END, risk_score DESC, "
    "file_path ASC, line ASC, id ASC",
    "file": "file_path ASC, line ASC, id ASC",
    "rule": "rule_id ASC, risk_score DESC, file_path ASC, id ASC",
}

_LIST_COLUMNS = (
    "id, scan_id, finding_id, rule_id, title, severity, risk_score, is_fp, is_error, error, file_path, line, "
    "cwe, cve, confidence, source_format, remediation_title"
)


def query_findings(
    conn: sqlite3.Connection,
    scan_id: int,
    *,
    q: str | None = None,
    band: str | None = None,
    status: str | None = "all",
    rule: str | None = None,
    file: str | None = None,
    sort: str = "risk",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Filter, sort and paginate a scan's findings. Returns ``{"items": [...], "total": n}``.

    ``band`` (high|medium|low) only matches assessed, non-FP findings. ``status`` is one of
    actionable|fp|error|all. ``q`` searches title, rule, file, message, CWE/CVE and finding id.
    ``rule`` matches exactly; ``file`` is a substring match. Unknown band/status/sort raise ValueError.
    """
    clauses = ["scan_id = ?"]
    params: list[Any] = [scan_id]
    status = status or "all"
    if status != "all":
        if status not in STATUS_SQL:
            raise ValueError(f"invalid status: {status}")
        clauses.append(STATUS_SQL[status])
    if band:
        if band not in BAND_SQL:
            raise ValueError(f"invalid band: {band}")
        clauses.append(f"{ACTIONABLE_SQL} AND {BAND_SQL[band]}")
    if sort not in FINDING_SORTS:
        raise ValueError(f"invalid sort: {sort}")
    if q:
        like = _like(q)
        fields = ("title", "rule_id", "file_path", "message", "cwe", "cve", "finding_id")
        clauses.append("(" + " OR ".join(f"COALESCE({c}, '') LIKE ? ESCAPE '\\'" for c in fields) + ")")
        params += [like] * len(fields)
    if rule:
        clauses.append("rule_id = ?")
        params.append(rule)
    if file:
        clauses.append("file_path LIKE ? ESCAPE '\\'")
        params.append(_like(file))

    where = " AND ".join(clauses)
    total = conn.execute(f"SELECT COUNT(*) FROM findings WHERE {where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT {_LIST_COLUMNS} FROM findings WHERE {where} ORDER BY {FINDING_SORTS[sort]} LIMIT ? OFFSET ?",
        (*params, _clamp(limit), max(0, int(offset))),
    ).fetchall()
    return {"items": [_decorate_finding(r) for r in rows], "total": int(total)}


def get_finding(conn: sqlite3.Connection, finding_row_id: int) -> dict | None:
    """Full detail for one stored finding (by row id), with its remediation card parsed."""
    row = conn.execute(
        """SELECT f.*, s.project, s.timestamp AS scan_timestamp, s.source_file, s.model
           FROM findings f JOIN scans s ON s.id = f.scan_id WHERE f.id = ?""",
        (finding_row_id,),
    ).fetchone()
    if row is None:
        return None
    d = _decorate_finding(row)
    raw = d.pop("remediation_json", None)
    remediation = None
    if raw:
        try:
            remediation = json.loads(raw)
        except ValueError:
            remediation = None
    if remediation is None and d.get("remediation_title"):
        remediation = {"title": d["remediation_title"], "business_impact": "", "steps": [],
                       "code_snippet": None, "reference_links": []}
    d["remediation"] = remediation
    return d
