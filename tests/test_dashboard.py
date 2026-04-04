"""Tests for the Flask dashboard app."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

flask = pytest.importorskip("flask")

from vulnsift.dashboard.app import create_app  # noqa: E402
from vulnsift.dashboard.db import init_db, store_report  # noqa: E402
from vulnsift.models import (  # noqa: E402
    Location,
    RemediationCard,
    TriageReport,
    TriageReportEntry,
    TriageResult,
    UnifiedFinding,
)

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "sample-triage-report.json"


def _make_report() -> TriageReport:
    return TriageReport(
        source_file="test.sarif",
        entries=[
            TriageReportEntry(
                finding=UnifiedFinding(
                    id="f1", rule_id="sql-injection", title="SQL Injection",
                    severity="high", location=Location(file_path="app.py"),
                    source_format="semgrep",
                ),
                triage=TriageResult(risk_score=9, reasoning="Exploitable."),
                remediation=RemediationCard(title="Fix it"),
            ),
        ],
    )


@pytest.fixture()
def client(tmp_path):
    db_path = tmp_path / "test.db"
    app = create_app(db_path=str(db_path))
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c, db_path


class TestDashboardRoutes:
    def test_index(self, client):
        c, _ = client
        resp = c.get("/")
        assert resp.status_code == 200
        assert b"VulnSift" in resp.data

    def test_api_scans_empty(self, client):
        c, _ = client
        resp = c.get("/api/scans")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_api_scans_with_data(self, client):
        c, db_path = client
        conn = init_db(str(db_path))
        store_report(conn, _make_report())
        conn.close()
        resp = c.get("/api/scans")
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["source_file"] == "test.sarif"

    def test_api_trends(self, client):
        c, db_path = client
        conn = init_db(str(db_path))
        store_report(conn, _make_report())
        conn.close()
        resp = c.get("/api/trends")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1

    def test_api_recurring(self, client):
        c, db_path = client
        conn = init_db(str(db_path))
        store_report(conn, _make_report())
        conn.close()
        resp = c.get("/api/recurring")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["rule_id"] == "sql-injection"

    def test_api_progress(self, client):
        c, db_path = client
        conn = init_db(str(db_path))
        store_report(conn, _make_report())
        conn.close()
        resp = c.get("/api/progress")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 1
        assert data["critical"] == 1

    def test_api_post_scan(self, client):
        c, _ = client
        report = _make_report()
        resp = c.post(
            "/api/scans",
            data=report.model_dump_json(),
            content_type="application/json",
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert "scan_id" in data

        # Verify it was stored
        resp2 = c.get("/api/scans")
        assert len(resp2.get_json()) == 1

    def test_api_post_invalid(self, client):
        c, _ = client
        resp = c.post(
            "/api/scans",
            data=json.dumps({"bad": "data"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
