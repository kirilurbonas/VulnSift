"""JSON export of full triage report."""

from __future__ import annotations

from pathlib import Path

from vulnsift.models import TriageReport


def export_report_json(report: TriageReport, path: str | Path) -> Path:
    """Write full triage report (all findings, including FPs) as JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump(mode="json")
    path.write_text(
        _json_dumps(payload),
        encoding="utf-8",
    )
    return path


def _json_dumps(obj: object) -> str:
    import json
    return json.dumps(obj, indent=2, default=str)
