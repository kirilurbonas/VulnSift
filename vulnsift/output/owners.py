"""Owner summary export helpers."""

from __future__ import annotations

import csv
import json
from io import StringIO

from vulnsift.codeowners import CodeownersRule, summarize_by_owner
from vulnsift.models import TriageReport


def render_owner_summary(
    report: TriageReport,
    rules: list[CodeownersRule],
    *,
    export_format: str = "json",
    min_risk: float = 0,
    top: int | None = None,
    unowned_label: str = "(unowned)",
) -> str:
    """Render owner rollups as JSON, CSV, or Markdown."""
    rows = summarize_by_owner(
        report,
        rules,
        min_risk=min_risk,
        limit=top,
        unowned_label=unowned_label,
    )
    if export_format == "json":
        return json.dumps(rows, indent=2)
    if export_format == "csv":
        return _render_csv(rows)
    if export_format == "md":
        return _render_markdown(rows)
    raise ValueError(f"Unsupported owner export format: {export_format}")


def _render_csv(rows: list[dict[str, object]]) -> str:
    buffer = StringIO()
    fieldnames = [
        "owners",
        "finding_count",
        "high_risk_count",
        "max_risk",
        "avg_risk",
        "total_risk",
        "top_files",
        "top_rules",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                **row,
                "top_files": " | ".join(str(item) for item in row["top_files"]),
                "top_rules": " | ".join(str(item) for item in row["top_rules"]),
            }
        )
    return buffer.getvalue()


def _render_markdown(rows: list[dict[str, object]]) -> str:
    lines = [
        "# VulnSift owner summary",
        "",
        "| Owners | Findings | High risk | Max risk | Top files |",
        "|--------|----------|-----------|----------|-----------|",
    ]
    for row in rows:
        lines.append(
            f"| {row['owners']} | {row['finding_count']} | {row['high_risk_count']} | "
            f"{row['max_risk']} | {', '.join(str(item) for item in row['top_files']) or '-'} |"
        )
    if not rows:
        lines.append("| No owner data found | 0 | 0 | 0 | - |")
    return "\n".join(lines) + "\n"
