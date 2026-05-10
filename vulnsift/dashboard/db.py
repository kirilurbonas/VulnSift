"""SQLite storage for scan history and dashboard queries."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from vulnsift.models import TriageReport

DEFAULT_DB_PATH = Path.home() / ".vulnsift" / "dashboard.db"

SCHEMA = """\
CREATE TABLE IF NOT EXISTS scans (
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

CREATE TABLE IF NOT EXISTS findings (
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


def init_db(db_path: Path | str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Initialise the database and return a connection."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def store_report(conn: sqlite3.Connection, report: TriageReport) -> int:
    """Store a triage report and return the scan ID."""
    non_fp = [e for e in report.entries if not e.triage.is_likely_false_positive]
    max_risk = max((e.triage.risk_score for e in non_fp), default=0)
    fp_count = sum(1 for e in report.entries if e.triage.is_likely_false_positive)

    cursor = conn.execute(
        """INSERT INTO scans (source_file, timestamp, schema_version, prompt_version,
           total_findings, actionable_findings, max_risk, false_positives)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            report.source_file,
            datetime.now(UTC).isoformat(),
            report.schema_version,
            report.prompt_version,
            len(report.entries),
            len(non_fp),
            max_risk,
            fp_count,
        ),
    )
    scan_id = cursor.lastrowid

    for entry in report.entries:
        f = entry.finding
        conn.execute(
            """INSERT INTO findings (scan_id, finding_id, rule_id, title, severity,
               risk_score, is_fp, file_path, cwe, remediation_title)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                f.id,
                f.rule_id,
                f.title,
                f.severity,
                entry.triage.risk_score,
                int(entry.triage.is_likely_false_positive),
                f.location.file_path,
                f.cwe,
                entry.remediation.title if entry.remediation else None,
            ),
        )

    conn.commit()
    return scan_id


def get_scan_history(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    """Return recent scans ordered by timestamp descending."""
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_risk_trends(conn: sqlite3.Connection, last_n: int = 20) -> list[dict]:
    """Return avg and max risk per scan for the last N scans."""
    rows = conn.execute(
        """SELECT s.id, s.timestamp, s.max_risk,
                  ROUND(AVG(f.risk_score), 1) as avg_risk,
                  COUNT(f.id) as finding_count
           FROM scans s
           LEFT JOIN findings f ON f.scan_id = s.id AND f.is_fp = 0
           GROUP BY s.id
           ORDER BY s.timestamp DESC
           LIMIT ?""",
        (last_n,),
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


def get_overview(conn: sqlite3.Connection) -> dict:
    """Return latest-scan overview plus simple deltas from the previous scan."""
    total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    latest_rows = conn.execute(
        "SELECT * FROM scans ORDER BY timestamp DESC, id DESC LIMIT 2"
    ).fetchall()

    if not latest_rows:
        return {
            "total_scans": 0,
            "latest_scan": None,
            "previous_scan": None,
            "deltas": {
                "total_findings": 0,
                "actionable_findings": 0,
                "max_risk": 0,
                "false_positives": 0,
                "critical_findings": 0,
            },
            "latest_risk_bands": {"critical": 0, "medium": 0, "low": 0},
        }

    latest = dict(latest_rows[0])
    previous = dict(latest_rows[1]) if len(latest_rows) > 1 else None

    latest_risk_bands = conn.execute(
        """SELECT
             SUM(CASE WHEN is_fp = 0 AND risk_score >= 7 THEN 1 ELSE 0 END) as critical,
             SUM(CASE WHEN is_fp = 0 AND risk_score >= 4 AND risk_score < 7 THEN 1 ELSE 0 END) as medium,
             SUM(CASE WHEN is_fp = 0 AND risk_score < 4 THEN 1 ELSE 0 END) as low
           FROM findings
           WHERE scan_id = ?""",
        (latest["id"],),
    ).fetchone()

    previous_bands = None
    if previous is not None:
        previous_bands = conn.execute(
            """SELECT
                 SUM(CASE WHEN is_fp = 0 AND risk_score >= 7 THEN 1 ELSE 0 END) as critical
               FROM findings
               WHERE scan_id = ?""",
            (previous["id"],),
        ).fetchone()

    deltas = {
        "total_findings": latest["total_findings"] - (previous["total_findings"] if previous else 0),
        "actionable_findings": latest["actionable_findings"] - (previous["actionable_findings"] if previous else 0),
        "max_risk": latest["max_risk"] - (previous["max_risk"] if previous else 0),
        "false_positives": latest["false_positives"] - (previous["false_positives"] if previous else 0),
        "critical_findings": (latest_risk_bands["critical"] or 0)
        - ((previous_bands["critical"] or 0) if previous_bands else 0),
    }

    return {
        "total_scans": total_scans,
        "latest_scan": latest,
        "previous_scan": previous,
        "deltas": deltas,
        "latest_risk_bands": {
            "critical": latest_risk_bands["critical"] or 0,
            "medium": latest_risk_bands["medium"] or 0,
            "low": latest_risk_bands["low"] or 0,
        },
    }


def get_top_recurring(conn: sqlite3.Connection, limit: int = 10) -> list[dict]:
    """Return the most frequently occurring rule_ids across all scans."""
    rows = conn.execute(
        """SELECT rule_id, title, COUNT(*) as occurrences,
                  MAX(risk_score) as max_risk,
                  COUNT(DISTINCT scan_id) as scan_count
           FROM findings
           WHERE is_fp = 0
           GROUP BY rule_id
           ORDER BY occurrences DESC
           LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_latest_hotspots(conn: sqlite3.Connection, limit: int = 8) -> list[dict]:
    """Return the riskiest files from the latest stored scan."""
    latest_scan = conn.execute("SELECT id FROM scans ORDER BY timestamp DESC, id DESC LIMIT 1").fetchone()
    if latest_scan is None:
        return []

    rows = conn.execute(
        """SELECT
             file_path,
             COUNT(*) as finding_count,
             SUM(CASE WHEN risk_score >= 7 THEN 1 ELSE 0 END) as high_risk_count,
             MAX(risk_score) as max_risk,
             ROUND(AVG(risk_score), 1) as avg_risk,
             SUM(risk_score) as total_risk
           FROM findings
           WHERE scan_id = ? AND is_fp = 0
           GROUP BY file_path
           ORDER BY total_risk DESC, max_risk DESC, finding_count DESC, file_path ASC
           LIMIT ?""",
        (latest_scan["id"], limit),
    ).fetchall()
    return [dict(r) for r in rows]


def get_latest_priorities(conn: sqlite3.Connection, limit: int = 8) -> list[dict]:
    """Return the highest-risk actionable findings from the latest scan."""
    latest_scan = conn.execute("SELECT id FROM scans ORDER BY timestamp DESC, id DESC LIMIT 1").fetchone()
    if latest_scan is None:
        return []

    rows = conn.execute(
        """SELECT
             finding_id,
             rule_id,
             title,
             risk_score,
             file_path,
             remediation_title
           FROM findings
           WHERE scan_id = ? AND is_fp = 0
           ORDER BY risk_score DESC, file_path ASC, rule_id ASC
           LIMIT ?""",
        (latest_scan["id"], limit),
    ).fetchall()
    return [dict(r) for r in rows]


def get_remediation_progress(conn: sqlite3.Connection) -> dict:
    """Return remediation progress stats."""
    row = conn.execute(
        """SELECT
             COUNT(*) as total,
             SUM(CASE WHEN is_fp = 1 THEN 1 ELSE 0 END) as false_positives,
             SUM(CASE WHEN is_fp = 0 AND risk_score >= 7 THEN 1 ELSE 0 END) as critical,
             SUM(CASE WHEN is_fp = 0 AND risk_score >= 4 AND risk_score < 7 THEN 1 ELSE 0 END) as medium,
             SUM(CASE WHEN is_fp = 0 AND risk_score < 4 THEN 1 ELSE 0 END) as low
           FROM findings"""
    ).fetchone()
    return dict(row) if row else {"total": 0, "false_positives": 0, "critical": 0, "medium": 0, "low": 0}
