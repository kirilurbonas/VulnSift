"""Flask web application for the VulnSift dashboard."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from vulnsift.dashboard.db import (
    get_remediation_progress,
    get_risk_trends,
    get_scan_history,
    get_top_recurring,
    init_db,
    store_report,
)
from vulnsift.models import TriageReport

try:
    from flask import Flask, jsonify, request, send_from_directory
except ImportError as e:
    raise ImportError(
        "Flask is required for the dashboard. Install with: pip install vulnsift[dashboard]"
    ) from e


def create_app(db_path: Path | str | None = None) -> Flask:
    """Create and configure the Flask app."""
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))

    conn: sqlite3.Connection | None = None

    def get_conn() -> sqlite3.Connection:
        nonlocal conn
        if conn is None:
            conn = init_db(db_path or Path.home() / ".vulnsift" / "dashboard.db")
        return conn

    @app.route("/")
    def index():
        return send_from_directory(app.template_folder, "index.html")

    @app.route("/api/scans")
    def api_scans():
        limit = request.args.get("limit", 50, type=int)
        return jsonify(get_scan_history(get_conn(), limit=limit))

    @app.route("/api/trends")
    def api_trends():
        last_n = request.args.get("last_n", 20, type=int)
        return jsonify(get_risk_trends(get_conn(), last_n=last_n))

    @app.route("/api/recurring")
    def api_recurring():
        limit = request.args.get("limit", 10, type=int)
        return jsonify(get_top_recurring(get_conn(), limit=limit))

    @app.route("/api/progress")
    def api_progress():
        return jsonify(get_remediation_progress(get_conn()))

    @app.route("/api/scans", methods=["POST"])
    def api_store_scan():
        data = request.get_json(force=True)
        try:
            report = TriageReport.model_validate(data)
        except Exception as e:
            return jsonify({"error": str(e)}), 400
        scan_id = store_report(get_conn(), report)
        return jsonify({"scan_id": scan_id}), 201

    return app
