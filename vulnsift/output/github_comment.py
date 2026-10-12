"""Render a GitHub PR comment from a VulnSift triage report."""

from __future__ import annotations

import html

from vulnsift.analytics import evaluate_gate, get_hotspots, get_priority_findings, summarize_report
from vulnsift.models import HIGH_RISK_THRESHOLD, MEDIUM_RISK_THRESHOLD, TriageReport, TriageReportEntry
from vulnsift.output.text import md_cell, md_code

COMMENT_MARKER = "<!-- vulnsift-triage -->"
TOP_FINDINGS = 15
DETAILED_FINDINGS = 5
# GitHub rejects comment bodies over 65,536 characters.
MAX_COMMENT_CHARS = 60_000


def _risk_display(score: int) -> str:
    if score >= HIGH_RISK_THRESHOLD:
        return f"**{score}** :red_circle:"
    if score >= MEDIUM_RISK_THRESHOLD:
        return f"{score} :orange_circle:"
    return f"{score} :green_circle:"


def _finding_details(entry: TriageReportEntry) -> list[str]:
    f = entry.finding
    loc = f.location.file_path or "(unknown file)"
    if f.location.start_line:
        loc += f":{f.location.start_line}"
    title = md_cell(entry.remediation.title if entry.remediation and entry.remediation.title else f.title, 100)
    out = [
        "<details>",
        f"<summary><strong>{entry.triage.risk_score}/10</strong> · {title} · <code>{html.escape(loc)}</code>"
        "</summary>",
        "",
    ]
    if entry.triage.reasoning:
        out.extend([f"**Why:** {html.escape(entry.triage.reasoning)}", ""])
    if entry.triage.exploitability_notes:
        out.extend([f"**Exploitability:** {html.escape(entry.triage.exploitability_notes)}", ""])
    if entry.remediation and entry.remediation.steps:
        out.append("**Fix:**")
        out.extend(f"{i}. {html.escape(step)}" for i, step in enumerate(entry.remediation.steps[:6], 1))
        out.append("")
    out.extend(["</details>", ""])
    return out


def render_github_comment(
    report: TriageReport,
    threshold: float | None = None,
    *,
    fail_on_error: bool = True,
) -> str:
    """Return GitHub-flavored Markdown for a PR comment summarising the triage report.

    Includes a hidden marker so the action can find and update existing comments.
    """
    entries = report.entries
    actionable = sorted((e for e in entries if e.is_actionable), key=lambda e: (-e.triage.risk_score, e.finding.id))
    summary = summarize_report(report)
    gate = evaluate_gate(report, threshold, fail_on_error=fail_on_error)

    if threshold is None:
        badge_line = ":information_source: **No gate threshold configured**"
    elif gate.passed:
        badge_line = f":white_check_mark: **Gate: PASSED** (threshold {threshold:g})"
    else:
        badge_line = f":x: **Gate: FAILED** (threshold {threshold:g}) — {md_cell(gate['reason'])}"

    lines: list[str] = [
        COMMENT_MARKER,
        "## VulnSift Triage Summary",
        "",
        badge_line,
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Findings analysed | {len(entries)} |",
        f"| Highest risk score | {summary['highest_risk']} |",
        f"| Actionable findings | {len(actionable)} |",
        f"| Likely false positives | {summary['false_positives']} |",
    ]
    if summary["errored_findings"]:
        lines.append(f"| :warning: Could not be triaged | {summary['errored_findings']} |")
    lines.extend([
        f"| Average actionable risk | {summary['average_risk']} |",
        (
            f"| Risk distribution | high {summary['risk_bands']['high']} / "
            f"medium {summary['risk_bands']['medium']} / low {summary['risk_bands']['low']} |"
        ),
        "",
    ])

    if actionable:
        lines.append("### Top findings")
        lines.append("")
        for entry in actionable[:DETAILED_FINDINGS]:
            lines.extend(_finding_details(entry))

        lines.append("<details>")
        lines.append(f"<summary><strong>All top findings ({len(actionable)} actionable)</strong></summary>")
        lines.append("")
        lines.append("| Risk | Rule | Title | File | Line |")
        lines.append("|------|------|-------|------|------|")
        for e in actionable[:TOP_FINDINGS]:
            lines.append(
                f"| {_risk_display(e.triage.risk_score)} | {md_code(e.finding.rule_id)} | "
                f"{md_cell(e.finding.title, 60)} | {md_code(e.finding.location.file_path or '-')} | "
                f"{e.finding.location.start_line or '-'} |"
            )
        if len(actionable) > TOP_FINDINGS:
            lines.append(f"\n*... and {len(actionable) - TOP_FINDINGS} more findings.*")
        lines.extend(["", "</details>", ""])

    hotspots = get_hotspots(report, limit=5)
    if hotspots:
        lines.extend([
            "<details>",
            "<summary><strong>Riskiest files</strong></summary>",
            "",
            "| File | Findings | High risk | Max risk |",
            "|------|----------|-----------|----------|",
        ])
        for hotspot in hotspots:
            lines.append(
                f"| {md_code(hotspot['file_path'])} | {hotspot['finding_count']} | "
                f"{hotspot['high_risk_count']} | {hotspot['max_risk']} |"
            )
        lines.extend(["", "</details>", ""])

    priorities = get_priority_findings(report, limit=5, min_risk=MEDIUM_RISK_THRESHOLD)
    if priorities:
        lines.extend([
            "<details>",
            "<summary><strong>Immediate priorities</strong></summary>",
            "",
            "| Risk | Rule | File | Suggested fix |",
            "|------|------|------|---------------|",
        ])
        for item in priorities:
            location = f"{item['file_path']}:{item['line']}" if item["line"] else str(item["file_path"])
            fix = item["remediation_title"] or "Review manually"
            lines.append(
                f"| {item['risk_score']} | {md_code(item['rule_id'])} | {md_code(location)} | {md_cell(fix, 80)} |"
            )
        lines.extend(["", "</details>", ""])

    errored = report.errored_entries
    if errored:
        lines.extend([
            "<details>",
            f"<summary><strong>:warning: {len(errored)} finding(s) could not be triaged</strong></summary>",
            "",
            "| Rule | File | Error |",
            "|------|------|-------|",
        ])
        for e in errored[:TOP_FINDINGS]:
            lines.append(
                f"| {md_code(e.finding.rule_id)} | {md_code(e.finding.location.file_path or '-')} | "
                f"{md_cell(e.triage.error, 120)} |"
            )
        lines.extend(["", "</details>", ""])

    footer = ["---", f"*Generated by [VulnSift](https://github.com/kirilurbonas/VulnSift)"
              f"{f' using `{report.model}`' if report.model else ''}*"]
    body = "\n".join(lines)
    if len(body) > MAX_COMMENT_CHARS:
        body = body[:MAX_COMMENT_CHARS].rsplit("\n", 1)[0] + "\n\n*Comment truncated; see the full report artifact.*\n"
    return body + "\n" + "\n".join(footer) + "\n"
