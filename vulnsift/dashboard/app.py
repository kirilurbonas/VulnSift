"""Flask web application for the VulnSift dashboard."""

from __future__ import annotations

import hmac
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from vulnsift.dashboard import db as dbmod
from vulnsift.dashboard.db import (
    DEFAULT_DB_PATH,
    MAX_PAGE_SIZE,
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
    query_findings,
    store_report,
)
from vulnsift.models import TriageReport

try:
    from flask import Flask, Response, abort, g, jsonify, request, send_from_directory
except ImportError as e:
    raise ImportError(
        "Flask is required for the dashboard. Install with: pip install vulnsift[dashboard]"
    ) from e

TOKEN_ENV_VAR = "VULNSIFT_DASHBOARD_TOKEN"
MAX_UPLOAD_BYTES = 64 * 1024 * 1024

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

_DB_KEY = "vulnsift_db"


def _json_error(message: str, status: int) -> tuple[Response, int]:
    return jsonify({"error": message}), status


def create_app(db_path: Path | str | None = None, *, token: str | None = None) -> Flask:
    """Create and configure the dashboard Flask app.

    ``db_path`` defaults to :data:`vulnsift.dashboard.db.DEFAULT_DB_PATH`. The schema is
    created/migrated once here; each request then opens its own SQLite connection.
    ``token`` (or ``$VULNSIFT_DASHBOARD_TOKEN``) protects POST/DELETE with ``Authorization: Bearer``.
    """
    here = Path(__file__).parent
    app = Flask(
        __name__,
        template_folder=str(here / "templates"),
        static_folder=str(here / "static"),
        static_url_path="/static",
    )
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.json.sort_keys = False

    resolved_path = str(db_path) if db_path is not None else str(DEFAULT_DB_PATH)
    if resolved_path == ":memory:":
        raise ValueError("The dashboard needs a file-backed database; ':memory:' is per-connection.")
    init_db(resolved_path).close()
    app.config["VULNSIFT_DB_PATH"] = resolved_path

    if token is None:
        token = os.environ.get(TOKEN_ENV_VAR) or None
    app.config["VULNSIFT_TOKEN"] = token or None

    # ---------------------------------------------------------------- per-request DB

    def get_db() -> sqlite3.Connection:
        conn = g.get(_DB_KEY)
        if conn is None:
            conn = dbmod.connect(app.config["VULNSIFT_DB_PATH"])
            setattr(g, _DB_KEY, conn)
        return conn

    @app.teardown_appcontext
    def close_db(_exc: BaseException | None) -> None:
        conn = g.pop(_DB_KEY, None)
        if conn is not None:
            conn.close()

    # ---------------------------------------------------------------- helpers

    def arg_int(name: str, default: int, *, lo: int = 1, hi: int = MAX_PAGE_SIZE) -> int:
        value = request.args.get(name, default, type=int)
        return max(lo, min(hi, value))

    def arg_project() -> str | None:
        project = request.args.get("project", "").strip()
        return project or None

    def arg_scan() -> int | None:
        return request.args.get("scan", None, type=int)

    def require_write_access() -> tuple[Response, int] | None:
        expected = app.config["VULNSIFT_TOKEN"]
        if expected:
            header = request.headers.get("Authorization", "")
            scheme, _, supplied = header.partition(" ")
            if scheme.lower() != "bearer" or not hmac.compare_digest(supplied.strip().encode(), expected.encode()):
                resp, status = _json_error("missing or invalid bearer token", 401)
                resp.headers["WWW-Authenticate"] = 'Bearer realm="vulnsift"'
                return resp, status
        # Defence in depth against cross-site requests: browsers always send Origin on
        # cross-origin POST/DELETE; reject any origin that is not this host.
        origin = request.headers.get("Origin")
        if origin and origin != "null" and urlsplit(origin).netloc != request.host:
            return _json_error("cross-origin request rejected", 403)
        if origin == "null":
            return _json_error("cross-origin request rejected", 403)
        return None

    @app.after_request
    def security_headers(resp: Response) -> Response:
        for header, value in SECURITY_HEADERS.items():
            resp.headers.setdefault(header, value)
        if request.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.errorhandler(404)
    def not_found(_e: Any):
        if request.path.startswith("/api/"):
            return _json_error("not found", 404)
        return "Not found", 404

    @app.errorhandler(405)
    def method_not_allowed(_e: Any):
        return _json_error("method not allowed", 405)

    @app.errorhandler(413)
    def too_large(_e: Any):
        return _json_error("payload too large", 413)

    # ---------------------------------------------------------------- pages

    @app.route("/")
    def index():
        resp = send_from_directory(app.template_folder, "index.html")
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    # ---------------------------------------------------------------- read API

    @app.get("/api/projects")
    def api_projects():
        return jsonify(list_projects(get_db()))

    @app.get("/api/scans")
    def api_scans():
        return jsonify(
            get_scan_history(
                get_db(),
                limit=arg_int("limit", 50),
                project=arg_project(),
                offset=request.args.get("offset", 0, type=int),
            )
        )

    @app.get("/api/scans/<int:scan_id>")
    def api_scan(scan_id: int):
        scan = get_scan(get_db(), scan_id)
        if scan is None:
            abort(404)
        return jsonify(scan)

    @app.get("/api/scans/<int:scan_id>/findings")
    def api_scan_findings(scan_id: int):
        conn = get_db()
        if get_scan(conn, scan_id) is None:
            abort(404)
        band = request.args.get("band", "").strip().lower() or None
        if band == "all":
            band = None
        try:
            result = query_findings(
                conn,
                scan_id,
                q=request.args.get("q", "").strip() or None,
                band=band,
                status=request.args.get("status", "all").strip().lower() or "all",
                rule=request.args.get("rule", "").strip() or None,
                file=request.args.get("file", "").strip() or None,
                sort=request.args.get("sort", "risk").strip().lower() or "risk",
                limit=arg_int("limit", 50),
                offset=arg_int("offset", 0, lo=0, hi=sys.maxsize),
            )
        except ValueError as exc:
            return _json_error(str(exc), 400)
        return jsonify(result)

    @app.get("/api/findings/<int:finding_id>")
    def api_finding(finding_id: int):
        finding = get_finding(get_db(), finding_id)
        if finding is None:
            abort(404)
        return jsonify(finding)

    @app.get("/api/overview")
    def api_overview():
        return jsonify(get_overview(get_db(), project=arg_project(), scan_id=arg_scan()))

    @app.get("/api/trends")
    def api_trends():
        return jsonify(get_risk_trends(get_db(), last_n=arg_int("last_n", 20), project=arg_project()))

    @app.get("/api/recurring")
    def api_recurring():
        return jsonify(get_top_recurring(get_db(), limit=arg_int("limit", 10), project=arg_project()))

    @app.get("/api/hotspots")
    def api_hotspots():
        return jsonify(
            get_latest_hotspots(get_db(), limit=arg_int("limit", 8), project=arg_project(), scan_id=arg_scan())
        )

    @app.get("/api/priorities")
    def api_priorities():
        return jsonify(
            get_latest_priorities(get_db(), limit=arg_int("limit", 8), project=arg_project(), scan_id=arg_scan())
        )

    @app.get("/api/progress")
    def api_progress():
        return jsonify(get_remediation_progress(get_db(), project=arg_project(), scan_id=arg_scan()))

    # ---------------------------------------------------------------- write API

    @app.post("/api/scans")
    def api_store_scan():
        denied = require_write_access()
        if denied:
            return denied
        if request.mimetype != "application/json":
            return _json_error("Content-Type must be application/json", 415)
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
            return _json_error("body must be a JSON triage report object with an 'entries' list", 400)
        try:
            report = TriageReport.model_validate(data)
        except ValidationError as exc:
            return _json_error(f"invalid triage report: {exc.error_count()} validation error(s)", 400)
        project = request.args.get("project", "").strip() or None
        scan_id = store_report(get_db(), report, project=project)
        return jsonify({"scan_id": scan_id}), 201

    @app.delete("/api/scans/<int:scan_id>")
    def api_delete_scan(scan_id: int):
        denied = require_write_access()
        if denied:
            return denied
        if not delete_scan(get_db(), scan_id):
            abort(404)
        return jsonify({"deleted": scan_id})

    return app


def serve(app: Flask, host: str = "127.0.0.1", port: int = 8080) -> None:
    """Serve the app with waitress when installed, else Flask's threaded dev server (with a warning)."""
    try:
        from waitress import serve as waitress_serve
    except ImportError:
        print(
            "WARNING: 'waitress' is not installed; using Flask's development server. "
            "Install it for production use: pip install waitress",
            file=sys.stderr,
        )
        app.run(host=host, port=port, threaded=True, debug=False, use_reloader=False)
        return
    waitress_serve(app, host=host, port=port, threads=8)
