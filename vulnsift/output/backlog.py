"""Prioritized backlog export helpers."""

from __future__ import annotations

import csv
import json
from io import StringIO
from pathlib import Path

from vulnsift.analytics import get_backlog_items
from vulnsift.codeowners import CodeownersRule, annotate_backlog_owners
from vulnsift.models import TriageReport


def render_backlog(
    report: TriageReport,
    *,
    export_format: str = "csv",
    top: int | None = None,
    min_risk: float = 4,
    owner_rules: list[CodeownersRule] | None = None,
    unowned_label: str = "(unowned)",
) -> str:
    """Render a prioritized backlog in CSV, JSON, or Markdown."""
    rows = _build_rows(
        report,
        top=top,
        min_risk=min_risk,
        owner_rules=owner_rules,
        unowned_label=unowned_label,
    )
    if export_format == "csv":
        return _render_csv(rows)
    if export_format == "json":
        return json.dumps(rows, indent=2)
    if export_format == "md":
        return _render_markdown(rows)
    raise ValueError(f"Unsupported backlog export format: {export_format}")


def write_backlog(
    report: TriageReport,
    path: str | Path,
    *,
    export_format: str = "csv",
    top: int | None = None,
    min_risk: float = 4,
    owner_rules: list[CodeownersRule] | None = None,
    unowned_label: str = "(unowned)",
) -> Path:
    """Write a prioritized backlog file and return the path."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        render_backlog(
            report,
            export_format=export_format,
            top=top,
            min_risk=min_risk,
            owner_rules=owner_rules,
            unowned_label=unowned_label,
        ),
        encoding="utf-8",
    )
    return output


def _build_rows(
    report: TriageReport,
    *,
    top: int | None,
    min_risk: float,
    owner_rules: list[CodeownersRule] | None,
    unowned_label: str,
) -> list[dict[str, object]]:
    items = get_backlog_items(report, limit=top, min_risk=min_risk)
    rows: list[dict[str, object]] = []
    for rank, item in enumerate(items, 1):
        rows.append(
            {
                "rank": rank,
                "risk_score": item["risk_score"],
                "rule_id": item["rule_id"],
                "finding_id": item["finding_id"],
                "title": item["title"],
                "file_path": item["file_path"],
                "line": item["line"],
                "severity": item["severity"],
                "source_format": item["source_format"],
                "cwe": item["cwe"] or "",
                "cve": item["cve"] or "",
                "remediation_title": item["remediation_title"] or "",
                "business_impact": item["business_impact"] or "",
                "step_count": item["step_count"],
                "recommended_steps": " | ".join(item["recommended_steps"]),
                "reference_links": " | ".join(item["references"]),
            }
        )
    if owner_rules:
        rows = annotate_backlog_owners(rows, owner_rules, unowned_label=unowned_label)
    return rows


def _render_csv(rows: list[dict[str, object]]) -> str:
    buffer = StringIO()
    fieldnames = [
        "rank",
        "risk_score",
        "owners",
        "rule_id",
        "finding_id",
        "title",
        "file_path",
        "line",
        "severity",
        "source_format",
        "cwe",
        "cve",
        "remediation_title",
        "business_impact",
        "step_count",
        "recommended_steps",
        "reference_links",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def _render_markdown(rows: list[dict[str, object]]) -> str:
    lines = [
        "# VulnSift prioritized backlog",
        "",
        "| Rank | Risk | Owners | Rule | File | Suggested fix |",
        "|------|------|--------|------|------|---------------|",
    ]
    for row in rows:
        line = f":{row['line']}" if row["line"] else ""
        lines.append(
            f"| {row['rank']} | {row['risk_score']} | {row.get('owners', '') or '-'} | `{row['rule_id']}` | "
            f"`{row['file_path']}{line}` | {row['remediation_title'] or 'Review manually'} |"
        )
    if not rows:
        lines.append("| - | - | - | - | - | No actionable findings at this threshold |")
    return "\n".join(lines) + "\n"
