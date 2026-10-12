"""Tests for the Flask dashboard app."""

from __future__ import annotations

import json
import re
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

flask = pytest.importorskip("flask")

from vulnsift.dashboard import app as app_module  # noqa: E402
from vulnsift.dashboard.app import create_app, serve  # noqa: E402
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


def _make_report(source: str = "test.sarif") -> TriageReport:
    return TriageReport(
        source_file=source,
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

    def test_api_overview(self, client):
        c, db_path = client
        conn = init_db(str(db_path))
        store_report(conn, _make_report())
        conn.close()
        resp = c.get("/api/overview")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_scans"] == 1
        assert data["latest_scan"]["source_file"] == "test.sarif"

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

    def test_api_hotspots(self, client):
        c, db_path = client
        conn = init_db(str(db_path))
        store_report(conn, _make_report())
        conn.close()
        resp = c.get("/api/hotspots")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["file_path"] == "app.py"

    def test_api_priorities(self, client):
        c, db_path = client
        conn = init_db(str(db_path))
        store_report(conn, _make_report())
        conn.close()
        resp = c.get("/api/priorities")
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
        assert data["new"] == 1
        assert data["previous_scan_id"] is None

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


# --------------------------------------------------------------------------------------
# New behaviour
# --------------------------------------------------------------------------------------

TOKEN = "s3cret-token"


def _entry(fid, rule, risk, *, file="app.py", fp=False, error=None, links=None, snippet=None):
    return TriageReportEntry(
        finding=UnifiedFinding(
            id=fid, rule_id=rule, title=f"{rule} issue", severity="high", cwe="CWE-89",
            location=Location(file_path=file, start_line=4, snippet=snippet), source_format="sarif",
        ),
        triage=TriageResult(
            risk_score=risk, is_likely_false_positive=fp, error=error,
            reasoning="Because.", exploitability_notes="Remote.", confidence=8,
        ),
        remediation=RemediationCard(
            title="Fix", steps=["a", "b"], reference_links=links or ["https://owasp.org", "javascript:alert(1)"],
        ),
    )


def _seed(db_path) -> dict[str, int]:
    conn = init_db(str(db_path))
    ids = {
        "alpha1": store_report(conn, _make_report(), project="alpha"),
        "beta1": store_report(
            conn,
            TriageReport(
                source_file="beta.sarif",
                entries=[
                    _entry("b1", "ssrf", 8, file="svc/fetch.py", snippet="requests.get(url)"),
                    _entry("b2", "xss", 5, file="web/view.py"),
                    _entry("b3", "noise", 1, file="tests/t.py", fp=True),
                    _entry("b4", "boom", 0, file="svc/fetch.py", error="rate limited"),
                ]
                + [_entry(f"p{i}", "weak-hash", 3, file=f"lib/m{i}.py") for i in range(30)],
            ),
            project="beta",
        ),
        "alpha2": store_report(conn, _make_report("second.sarif"), project="alpha"),
    }
    conn.close()
    return ids


@pytest.fixture()
def seeded(tmp_path):
    db_path = tmp_path / "seeded.db"
    ids = _seed(db_path)
    app = create_app(db_path=str(db_path))
    with app.test_client() as c:
        yield c, ids


@pytest.fixture()
def secured(tmp_path):
    app = create_app(db_path=str(tmp_path / "auth.db"), token=TOKEN)
    with app.test_client() as c:
        yield c


def _post(c, payload, *, token=None, content_type="application/json", **kw):
    headers = kw.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return c.post("/api/scans", data=payload, content_type=content_type, headers=headers, **kw)


class TestStaticAndHeaders:
    def test_security_headers(self, client):
        c, _ = client
        for path in ("/", "/api/overview", "/static/app.js", "/api/nope"):
            resp = c.get(path)
            csp = resp.headers["Content-Security-Policy"]
            assert "frame-ancestors 'none'" in csp
            assert "script-src 'self'" in csp
            assert "default-src 'none'" in csp
            assert resp.headers["X-Content-Type-Options"] == "nosniff"
            assert resp.headers["Referrer-Policy"] == "no-referrer"
        assert c.get("/api/overview").headers["Cache-Control"] == "no-store"

    def test_static_assets_served(self, client):
        c, _ = client
        js = c.get("/static/app.js")
        assert js.status_code == 200
        assert "function esc(" in js.get_data(as_text=True)
        assert c.get("/static/app.css").status_code == 200

    def test_no_external_network_dependencies(self):
        root = Path(app_module.__file__).parent
        for path in [root / "templates" / "index.html", *sorted((root / "static").glob("*"))]:
            text = path.read_text()
            urls = re.findall(r"""(?:src|href)\s*=\s*["'](https?:)?//""", text)
            assert not urls, f"external asset reference in {path.name}"
            assert "googleapis" not in text and "jsdelivr" not in text and "cdn." not in text
            if path.suffix == ".html":
                assert "<script>" not in text and "<style" not in text  # CSP: no inline code
                assert " style=" not in text

    def test_unknown_api_route_is_json_404(self, client):
        c, _ = client
        resp = c.get("/api/scans/12345")
        assert resp.status_code == 404
        assert resp.get_json() == {"error": "not found"}


class TestWriteProtection:
    def test_text_plain_rejected(self, client):
        c, _ = client
        resp = _post(c, _make_report().model_dump_json(), content_type="text/plain")
        assert resp.status_code == 415
        assert c.get("/api/scans").get_json() == []

    def test_form_rejected(self, client):
        c, _ = client
        resp = c.post("/api/scans", data={"entries": "[]"})
        assert resp.status_code == 415

    def test_non_object_payloads(self, client):
        c, _ = client
        for body in ("[]", '"x"', "not json", "{", json.dumps({"entries": "nope"})):
            assert _post(c, body).status_code == 400, body
        bad_entry = {"entries": [{"finding": {}, "triage": {"risk_score": 99}}]}
        resp = _post(c, json.dumps(bad_entry))
        assert resp.status_code == 400
        assert "error" in resp.get_json()

    def test_post_with_project_query(self, client):
        c, _ = client
        resp = c.post("/api/scans?project=web", data=_make_report().model_dump_json(),
                      content_type="application/json")
        assert resp.status_code == 201
        assert c.get("/api/projects").get_json()[0]["project"] == "web"

    def test_cross_origin_rejected(self, client):
        c, _ = client
        resp = _post(c, _make_report().model_dump_json(), headers={"Origin": "https://evil.example"})
        assert resp.status_code == 403
        resp = _post(c, _make_report().model_dump_json(), headers={"Origin": "null"})
        assert resp.status_code == 403
        resp = _post(c, _make_report().model_dump_json(), headers={"Origin": "http://localhost"})
        assert resp.status_code == 201

    def test_token_required(self, secured):
        c = secured
        body = _make_report().model_dump_json()
        assert _post(c, body).status_code == 401
        assert _post(c, body, token="wrong").status_code == 401
        assert _post(c, body, headers={"Authorization": TOKEN}).status_code == 401
        resp = _post(c, body, token=TOKEN)
        assert resp.status_code == 201
        scan_id = resp.get_json()["scan_id"]
        # Reads stay open.
        assert c.get("/api/scans").status_code == 200
        assert c.delete(f"/api/scans/{scan_id}").status_code == 401
        assert c.delete(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200

    def test_auth_checked_before_content_type(self, secured):
        resp = _post(secured, "x", content_type="text/plain")
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"].startswith("Bearer")

    def test_token_from_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VULNSIFT_DASHBOARD_TOKEN", "envtok")
        app = create_app(db_path=str(tmp_path / "e.db"))
        c = app.test_client()
        assert _post(c, _make_report().model_dump_json()).status_code == 401
        assert _post(c, _make_report().model_dump_json(), token="envtok").status_code == 201

    def test_no_token_by_default(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VULNSIFT_DASHBOARD_TOKEN", raising=False)
        c = create_app(db_path=str(tmp_path / "e.db")).test_client()
        assert _post(c, _make_report().model_dump_json()).status_code == 201

    def test_memory_db_rejected(self):
        with pytest.raises(ValueError):
            create_app(db_path=":memory:")


class TestDeleteEndpoint:
    def test_delete_cascades(self, seeded):
        c, ids = seeded
        detail_ids = [i["id"] for i in c.get(f"/api/scans/{ids['beta1']}/findings").get_json()["items"]]
        resp = c.delete(f"/api/scans/{ids['beta1']}")
        assert resp.status_code == 200
        assert resp.get_json() == {"deleted": ids["beta1"]}
        assert c.get(f"/api/scans/{ids['beta1']}").status_code == 404
        assert c.get(f"/api/findings/{detail_ids[0]}").status_code == 404
        assert [p["project"] for p in c.get("/api/projects").get_json()] == ["alpha"]
        assert c.delete(f"/api/scans/{ids['beta1']}").status_code == 404


class TestReadEndpoints:
    def test_projects(self, seeded):
        c, ids = seeded
        projects = c.get("/api/projects").get_json()
        assert [p["project"] for p in projects] == ["alpha", "beta"]
        assert projects[0]["latest_scan_id"] == ids["alpha2"]
        assert projects[0]["scan_count"] == 2

    def test_project_filters(self, seeded):
        c, ids = seeded
        assert len(c.get("/api/scans?project=alpha").get_json()) == 2
        assert len(c.get("/api/scans?project=beta").get_json()) == 1
        assert len(c.get("/api/scans").get_json()) == 3
        assert len(c.get("/api/trends?project=alpha").get_json()) == 2
        overview = c.get("/api/overview?project=beta").get_json()
        assert overview["latest_scan"]["id"] == ids["beta1"]
        assert overview["latest_scan"]["errored_findings"] == 1
        assert overview["latest_risk_bands"]["errors"] == 1
        assert overview["total_scans"] == 1
        assert c.get("/api/hotspots?project=beta").get_json()[0]["file_path"] == "svc/fetch.py"
        assert c.get("/api/priorities?project=beta").get_json()[0]["rule_id"] == "ssrf"
        rules = {r["rule_id"] for r in c.get("/api/recurring?project=alpha").get_json()}
        assert rules == {"sql-injection"}
        progress = c.get("/api/progress?project=alpha").get_json()
        assert progress["previous_scan_id"] == ids["alpha1"]
        assert progress["recurring"] == 1 and progress["new"] == 0 and progress["resolved"] == 0

    def test_scan_param(self, seeded):
        c, ids = seeded
        overview = c.get(f"/api/overview?scan={ids['alpha1']}").get_json()
        assert overview["latest_scan"]["id"] == ids["alpha1"]
        assert c.get(f"/api/priorities?scan={ids['beta1']}").get_json()[0]["rule_id"] == "ssrf"

    def test_scan_detail(self, seeded):
        c, ids = seeded
        scan = c.get(f"/api/scans/{ids['alpha2']}").get_json()
        assert scan["project"] == "alpha"
        assert scan["previous_scan_id"] == ids["alpha1"]
        assert scan["risk_bands"]["critical"] == 1

    def test_findings_endpoint(self, seeded):
        c, ids = seeded
        base = f"/api/scans/{ids['beta1']}/findings"
        data = c.get(base).get_json()
        assert set(data) == {"items", "total"}
        assert data["total"] == 34
        assert len(data["items"]) == 34
        assert data["items"][0]["rule_id"] == "ssrf"
        assert c.get(base + "?status=error").get_json()["items"][0]["error"] == "rate limited"
        assert c.get(base + "?status=fp").get_json()["total"] == 1
        assert c.get(base + "?status=actionable").get_json()["total"] == 32
        assert c.get(base + "?band=high").get_json()["total"] == 1
        assert c.get(base + "?band=medium").get_json()["total"] == 1
        assert c.get(base + "?band=low&status=actionable").get_json()["total"] == 30
        assert c.get(base + "?band=all").get_json()["total"] == 34
        assert c.get(base + "?q=fetch").get_json()["total"] == 2
        assert c.get(base + "?rule=weak-hash").get_json()["total"] == 30
        assert c.get(base + "?file=lib/").get_json()["total"] == 30
        page = c.get(base + "?rule=weak-hash&sort=file&limit=10&offset=20").get_json()
        assert page["total"] == 30 and len(page["items"]) == 10
        files = [i["file_path"] for i in page["items"]]
        assert files == sorted(files)
        for bad in ("band=critical", "status=x", "sort=id"):
            assert c.get(f"{base}?{bad}").status_code == 400
        assert c.get("/api/scans/999/findings").status_code == 404

    def test_finding_detail(self, seeded):
        c, ids = seeded
        items = c.get(f"/api/scans/{ids['beta1']}/findings?q=ssrf").get_json()["items"]
        detail = c.get(f"/api/findings/{items[0]['id']}").get_json()
        assert detail["reasoning"] == "Because."
        assert detail["exploitability_notes"] == "Remote."
        assert detail["confidence"] == 8
        assert detail["snippet"] == "requests.get(url)"
        assert detail["remediation"]["steps"] == ["a", "b"]
        assert detail["remediation"]["reference_links"][0] == "https://owasp.org"
        assert detail["cwe"] == "CWE-89"
        assert detail["severity"] == "high"
        assert detail["band"] == "high" and detail["status"] == "actionable"
        assert detail["project"] == "beta"
        assert "remediation_json" not in detail
        err = c.get(f"/api/scans/{ids['beta1']}/findings?status=error").get_json()["items"][0]
        err_detail = c.get(f"/api/findings/{err['id']}").get_json()
        assert err_detail["status"] == "error" and err_detail["is_error"] is True
        assert err_detail["band"] is None
        assert c.get("/api/findings/999999").status_code == 404

    def test_limit_clamping(self, tmp_path):
        db_path = tmp_path / "many.db"
        conn = init_db(str(db_path))
        many = TriageReport(entries=[_entry(f"x{i}", f"r{i}", 5) for i in range(600)])
        scan_id = store_report(conn, many)
        for _ in range(3):
            store_report(conn, _make_report())
        conn.close()
        c = create_app(db_path=str(db_path)).test_client()
        assert len(c.get("/api/scans?limit=0").get_json()) == 1
        assert len(c.get("/api/scans?limit=-1").get_json()) == 1
        assert len(c.get("/api/scans?limit=abc").get_json()) == 4  # default
        assert len(c.get("/api/trends?last_n=0").get_json()) == 1
        assert len(c.get("/api/trends?last_n=99999").get_json()) == 4
        assert len(c.get(f"/api/hotspots?scan={scan_id}&limit=100000").get_json()) == 1
        assert len(c.get(f"/api/priorities?scan={scan_id}&limit=100000").get_json()) == 500
        assert len(c.get("/api/recurring?limit=100000").get_json()) == 500
        page = c.get(f"/api/scans/{scan_id}/findings?limit=100000").get_json()
        assert page["total"] == 600 and len(page["items"]) == 500
        assert len(c.get(f"/api/scans/{scan_id}/findings?limit=0").get_json()["items"]) == 1
        assert len(c.get(f"/api/scans/{scan_id}/findings?offset=-5&limit=2").get_json()["items"]) == 2

    def test_errored_counted_separately_via_post(self, client):
        c, _ = client
        report = TriageReport(entries=[_entry("a", "x", 9), _entry("b", "y", 0, error="boom"),
                                       _entry("c", "z", 0, fp=True)])
        assert _post(c, report.model_dump_json()).status_code == 201
        scan = c.get("/api/scans").get_json()[0]
        assert scan["errored_findings"] == 1
        assert scan["false_positives"] == 1
        assert scan["actionable_findings"] == 1


class TestConcurrency:
    def test_threaded_server_parallel_requests(self, tmp_path):
        from werkzeug.serving import make_server

        db_path = tmp_path / "conc.db"
        _seed(db_path)
        app = create_app(db_path=str(db_path))
        server = make_server("127.0.0.1", 0, app, threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        report_body = _make_report().model_dump_json().encode()

        def hit(i: int) -> int:
            if i % 10 == 0:
                req = urllib.request.Request(
                    f"{base}/api/scans", data=report_body, method="POST",
                    headers={"Content-Type": "application/json"},
                )
            else:
                path = ["/api/overview", "/api/trends", "/api/hotspots", "/api/priorities", "/api/recurring",
                        "/api/progress", "/api/scans", "/api/projects", "/api/scans/1/findings"][i % 9]
                req = urllib.request.Request(base + path)
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    json.loads(resp.read())
                    return resp.status
            except urllib.error.HTTPError as e:  # pragma: no cover - surfaced in the assertion
                return e.code

        try:
            with ThreadPoolExecutor(max_workers=24) as pool:
                statuses = list(pool.map(hit, range(240)))
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert all(s in (200, 201) for s in statuses), sorted(set(statuses))
        conn = init_db(str(db_path))
        assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 3 + 24
        conn.close()


class TestServe:
    def test_falls_back_to_flask_with_warning(self, monkeypatch, capsys, tmp_path):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "waitress":
                raise ImportError("no waitress")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        app = create_app(db_path=str(tmp_path / "s.db"))
        calls = {}
        monkeypatch.setattr(app, "run", lambda **kw: calls.update(kw))
        serve(app, "127.0.0.1", 9999)
        assert calls["threaded"] is True and calls["port"] == 9999 and calls["debug"] is False
        assert "waitress" in capsys.readouterr().err

    def test_uses_waitress_when_available(self, monkeypatch, tmp_path):
        import sys
        import types

        calls = {}
        fake = types.ModuleType("waitress")
        fake.serve = lambda app, **kw: calls.update(kw, app=app)
        monkeypatch.setitem(sys.modules, "waitress", fake)
        app = create_app(db_path=str(tmp_path / "s.db"))
        serve(app, "0.0.0.0", 8081)
        assert calls["app"] is app and calls["host"] == "0.0.0.0" and calls["port"] == 8081
