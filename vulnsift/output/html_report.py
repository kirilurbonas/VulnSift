"""Standalone HTML report rendering."""

from __future__ import annotations

from html import escape

from vulnsift.analytics import compare_reports, get_backlog_items, get_hotspots, summarize_report
from vulnsift.codeowners import CodeownersRule, annotate_backlog_owners, summarize_by_owner
from vulnsift.models import MEDIUM_RISK_THRESHOLD, TriageReport, TriageReportEntry, risk_band


def render_html_report(
    report: TriageReport,
    *,
    baseline: TriageReport | None = None,
    title: str | None = None,
    top_n: int = 10,
    owner_rules: list[CodeownersRule] | None = None,
    unowned_label: str = "(unowned)",
) -> str:
    """Render a standalone HTML artifact for sharing triage results."""
    summary = summarize_report(report)
    hotspots = get_hotspots(report, limit=top_n)
    backlog = get_backlog_items(report, limit=top_n, min_risk=MEDIUM_RISK_THRESHOLD)
    if owner_rules:
        backlog = annotate_backlog_owners(backlog, owner_rules, unowned_label=unowned_label)
    owner_summary = (
        summarize_by_owner(report, owner_rules, min_risk=0, limit=top_n, unowned_label=unowned_label)
        if owner_rules
        else []
    )
    comparison = compare_reports(report, baseline) if baseline is not None else None

    page_title = title or "VulnSift Report"
    source_file = report.source_file or "Unknown source"
    risk_bands = summary["risk_bands"]

    comparison_html = ""
    if comparison is not None:
        comparison_summary = comparison["summary"]
        comparison_trend = escape(str(comparison["trend"]))
        comparison_trend_label = escape(str(comparison["trend"]).upper())
        new_findings_html = _render_change_table(
            "New actionable findings",
            comparison["new_findings"][:top_n],
            "No new actionable findings.",
        )
        resolved_findings_html = _render_change_table(
            "Resolved actionable findings",
            comparison["resolved_findings"][:top_n],
            "No resolved actionable findings.",
        )
        escalated_findings_html = _render_delta_table(
            "Escalated findings",
            comparison["escalated_findings"][:top_n],
            "No escalating findings.",
        )
        comparison_html = f"""
        <section class="panel">
          <div class="section-head">
            <div>
              <h2>Baseline Comparison</h2>
              <p>Compared against {escape(baseline.source_file or "baseline report")}.</p>
            </div>
            <span class="trend trend-{comparison_trend}">{comparison_trend_label}</span>
          </div>
          <div class="card-grid compact">
            {_metric_card("Actionable delta", _signed(int(comparison_summary["actionable_delta"])))}
            {_metric_card("Total risk delta", _signed(int(comparison_summary["risk_delta"])))}
            {_metric_card("New findings", str(comparison_summary["new_actionable"]))}
            {_metric_card("Resolved findings", str(comparison_summary["resolved_actionable"]))}
          </div>
          {new_findings_html}
          {resolved_findings_html}
          {escalated_findings_html}
        </section>
        """

    owner_summary_html = ""
    if owner_summary:
        owner_summary_html = f"""
        <section class="panel">
          <div class="section-head">
            <div>
              <h2>Owner Rollup</h2>
              <p>Actionable risk grouped by CODEOWNERS ownership.</p>
            </div>
          </div>
          {_render_owner_summary_table(owner_summary)}
        </section>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{escape(page_title)}</title>
  <style>
    :root {{
      --bg: #f4f6fb;
      --panel: #ffffff;
      --panel-soft: #f8fafc;
      --ink: #132033;
      --muted: #58667a;
      --line: #d9e1ec;
      --accent: #0f766e;
      --danger: #c2410c;
      --danger-bg: #ffedd5;
      --warning: #b45309;
      --warning-bg: #fef3c7;
      --success: #166534;
      --success-bg: #dcfce7;
      --shadow: 0 20px 60px rgba(15, 23, 42, 0.08);
      --hero-top: #eef5ff;
      --error: #86198f;
      --error-bg: #fae8ff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: linear-gradient(180deg, var(--hero-top) 0%, var(--bg) 100%);
      color: var(--ink);
      line-height: 1.55;
    }}
    .page {{ max-width: 1180px; margin: 0 auto; padding: 32px 16px 48px; }}
    .hero {{
      padding: 28px;
      border-radius: 24px;
      background: linear-gradient(135deg, rgba(15, 118, 110, 0.12), rgba(255, 255, 255, 0.94));
      border: 1px solid rgba(15, 118, 110, 0.12);
      box-shadow: var(--shadow);
      margin-bottom: 18px;
    }}
    .hero h1 {{ margin: 0 0 8px; font-size: clamp(2rem, 5vw, 3.5rem); line-height: 0.95; }}
    .hero p {{ margin: 0; color: var(--muted); max-width: 70ch; }}
    .hero-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 18px;
      color: var(--muted);
      font-size: 0.95rem;
    }}
    .hero-meta span {{
      padding: 10px 14px;
      background: rgba(255, 255, 255, 0.75);
      border: 1px solid rgba(19, 32, 51, 0.08);
      border-radius: 999px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 22px;
      box-shadow: var(--shadow);
      padding: 22px;
      margin-top: 18px;
    }}
    .card-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-top: 18px;
    }}
    .card-grid.compact {{ grid-template-columns: repeat(4, minmax(0, 1fr)); }}
    .metric {{
      background: var(--panel-soft);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 16px;
    }}
    .metric span {{
      display: block;
      color: var(--muted);
      font-size: 0.84rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .metric strong {{
      display: block;
      margin-top: 8px;
      font-size: 2rem;
      line-height: 1;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: flex-start;
      margin-bottom: 16px;
    }}
    .section-head h2 {{ margin: 0; font-size: 1.2rem; }}
    .section-head p {{ margin: 6px 0 0; color: var(--muted); }}
    .trend {{
      padding: 10px 14px;
      border-radius: 999px;
      font-weight: 700;
      font-size: 0.82rem;
      letter-spacing: 0.06em;
    }}
    .trend-improved {{ background: var(--success-bg); color: var(--success); }}
    .trend-worsened {{ background: var(--danger-bg); color: var(--danger); }}
    .trend-stable {{ background: var(--warning-bg); color: var(--warning); }}
    .split {{
      display: grid;
      grid-template-columns: 1.2fr 1fr;
      gap: 18px;
    }}
    .pill-row {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }}
    .pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: var(--panel-soft);
      color: var(--muted);
      font-size: 0.92rem;
      font-weight: 600;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.93rem;
    }}
    th, td {{
      padding: 12px 10px;
      text-align: left;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }}
    th {{
      font-size: 0.74rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
    }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 0.84rem;
    }}
    .risk {{
      display: inline-flex;
      min-width: 44px;
      justify-content: center;
      padding: 4px 10px;
      border-radius: 999px;
      font-weight: 700;
    }}
    .risk-high {{ background: var(--danger-bg); color: var(--danger); }}
    .risk-med {{ background: var(--warning-bg); color: var(--warning); }}
    .risk-low {{ background: var(--success-bg); color: var(--success); }}
    .empty {{
      margin: 0;
      padding: 16px;
      border-radius: 14px;
      background: var(--panel-soft);
      border: 1px dashed var(--line);
      color: var(--muted);
    }}
    .footer {{ margin-top: 20px; color: var(--muted); font-size: 0.9rem; text-align: center; }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #0b1220; --panel: #111a2c; --panel-soft: #16213a; --ink: #e5ecf6; --muted: #9aa8bd;
        --line: #26334d; --accent: #2dd4bf; --danger: #fdba74; --danger-bg: #431407; --warning: #fcd34d;
        --warning-bg: #422006; --success: #86efac; --success-bg: #052e16; --hero-top: #0f1b33;
        --error: #f0abfc; --error-bg: #3b0764; --shadow: none;
      }}
    }}
    details.finding {{ border: 1px solid var(--line); border-radius: 14px; margin: 10px 0;
      background: var(--panel-soft); }}
    details.finding summary {{ cursor: pointer; padding: 12px 14px; display: flex; gap: 10px; align-items: center;
      flex-wrap: wrap; }}
    details.finding .body {{ padding: 0 16px 14px; }}
    details.finding h4 {{ margin: 12px 0 4px; font-size: 0.95rem; }}
    details.finding p, details.finding li {{ color: var(--ink); line-height: 1.5; }}
    details.finding pre {{ overflow-x: auto; padding: 10px; border-radius: 10px; background: var(--panel);
      border: 1px solid var(--line); }}
    .risk-err {{ background: var(--error-bg); color: var(--error); }}
    .muted {{ color: var(--muted); }}
    code {{ overflow-wrap: anywhere; }}
    @media (max-width: 900px) {{
      .card-grid, .card-grid.compact, .split {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <h1>{escape(page_title)}</h1>
      <p>Shareable vulnerability triage report generated by VulnSift with prioritized remediation guidance.</p>
      <div class="hero-meta">
        <span>Source: <code>{escape(source_file)}</code></span>
        <span>Actionable findings: {escape(str(summary["actionable_findings"]))}</span>
        <span>Highest risk: {escape(str(summary["highest_risk"]))}</span>
      </div>
    </section>

    <section class="panel">
      <div class="section-head">
        <div>
          <h2>Executive Summary</h2>
          <p>High-signal overview for security and engineering stakeholders.</p>
        </div>
      </div>
      <div class="card-grid">
        {_metric_card("Actionable findings", str(summary["actionable_findings"]))}
        {_metric_card("Likely false positives", str(summary["false_positives"]))}
        {_metric_card("Highest risk", str(summary["highest_risk"]))}
        {_metric_card("Average actionable risk", str(summary["average_risk"]))}
        {_metric_card("Could not be triaged", str(summary["errored_findings"])) if summary["errored_findings"] else ""}
      </div>
      <div class="pill-row">
        <span class="pill">High risk: {escape(str(risk_bands["high"]))}</span>
        <span class="pill">Medium risk: {escape(str(risk_bands["medium"]))}</span>
        <span class="pill">Low risk: {escape(str(risk_bands["low"]))}</span>
        <span class="pill">Scanner mix: {escape(_scanner_mix(summary["source_formats"]))}</span>
      </div>
    </section>

    <section class="split">
      <section class="panel">
        <div class="section-head">
          <div>
            <h2>Hotspots</h2>
            <p>Files carrying the heaviest actionable risk concentration.</p>
          </div>
        </div>
        {_render_hotspots_table(hotspots)}
      </section>

      <section class="panel">
        <div class="section-head">
          <div>
            <h2>Priority Backlog</h2>
            <p>The next fixes that will move risk down fastest.</p>
          </div>
        </div>
        {_render_backlog_table(backlog)}
      </section>
    </section>

    <section class="panel">
      <div class="section-head">
        <div>
          <h2>Findings</h2>
          <p>Every actionable finding with the AI's reasoning and remediation. Click to expand.</p>
        </div>
      </div>
      {_render_findings_detail(report)}
    </section>

    {owner_summary_html}

    {comparison_html}

    <p class="footer">
      Generated by VulnSift. Use this artifact in CI, share it internally, or attach it to remediation planning.
    </p>
  </main>
</body>
</html>
"""


def _render_hotspots_table(hotspots: list[dict[str, object]]) -> str:
    if not hotspots:
        return '<p class="empty">No hotspot data available for this report.</p>'
    rows = []
    for hotspot in hotspots:
        rows.append(
            "<tr>"
            f"<td><code>{escape(str(hotspot['file_path']))}</code></td>"
            f"<td>{escape(str(hotspot['finding_count']))}</td>"
            f"<td>{escape(str(hotspot['high_risk_count']))}</td>"
            f"<td>{_risk_badge(int(hotspot['max_risk']))}</td>"
            f"<td>{escape(str(hotspot['avg_risk']))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>File</th><th>Findings</th><th>High risk</th><th>Max risk</th><th>Avg risk</th></tr>"
        "</thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _render_backlog_table(backlog: list[dict[str, object]]) -> str:
    if not backlog:
        return '<p class="empty">No actionable findings at this threshold.</p>'
    rows = []
    for item in backlog:
        line = f":{item['line']}" if item["line"] else ""
        owners = escape(str(item.get("owners", ""))) if item.get("owners") else "-"
        rows.append(
            "<tr>"
            f"<td>{_risk_badge(int(item['risk_score']))}</td>"
            f"<td><code>{escape(str(item['rule_id']))}</code><br>{escape(str(item['title']))}</td>"
            f"<td><code>{escape(str(item['file_path']))}{escape(line)}</code></td>"
            f"<td>{owners}</td>"
            f"<td>{escape(str(item['remediation_title'] or 'Review manually'))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Risk</th><th>Finding</th><th>Location</th><th>Owners</th><th>Suggested fix</th></tr>"
        "</thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _render_change_table(title: str, items: list[dict[str, object]], empty_message: str) -> str:
    if not items:
        return f'<section><h3>{escape(title)}</h3><p class="empty">{escape(empty_message)}</p></section>'
    rows = []
    for item in items:
        line = f":{item['line']}" if item["line"] else ""
        rows.append(
            "<tr>"
            f"<td>{_risk_badge(int(item['risk_score']))}</td>"
            f"<td><code>{escape(str(item['rule_id']))}</code></td>"
            f"<td><code>{escape(str(item['file_path']))}{escape(line)}</code></td>"
            f"<td>{escape(str(item['remediation_title'] or 'Review manually'))}</td>"
            "</tr>"
        )
    return (
        f"<section><h3>{escape(title)}</h3>"
        "<table><thead><tr><th>Risk</th><th>Rule</th><th>Location</th><th>Suggested fix</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></section>"
    )


def _render_delta_table(title: str, items: list[dict[str, object]], empty_message: str) -> str:
    if not items:
        return f'<section><h3>{escape(title)}</h3><p class="empty">{escape(empty_message)}</p></section>'
    rows = []
    for item in items:
        line = f":{item['line']}" if item["line"] else ""
        rows.append(
            "<tr>"
            f"<td>{escape(_signed(int(item['risk_delta'])))}</td>"
            f"<td>{_risk_badge(int(item['risk_score']))}</td>"
            f"<td><code>{escape(str(item['rule_id']))}</code></td>"
            f"<td><code>{escape(str(item['file_path']))}{escape(line)}</code></td>"
            "</tr>"
        )
    return (
        f"<section><h3>{escape(title)}</h3>"
        "<table><thead><tr><th>Delta</th><th>Current risk</th><th>Rule</th><th>Location</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></section>"
    )


def _render_owner_summary_table(rows: list[dict[str, object]]) -> str:
    if not rows:
        return '<p class="empty">No owner summary data available.</p>'
    body = []
    for row in rows:
        body.append(
            "<tr>"
            f"<td>{escape(str(row['owners']))}</td>"
            f"<td>{escape(str(row['finding_count']))}</td>"
            f"<td>{escape(str(row['high_risk_count']))}</td>"
            f"<td>{_risk_badge(int(row['max_risk']))}</td>"
            f"<td>{escape(', '.join(str(item) for item in row['top_files']) or '-')}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Owners</th><th>Findings</th><th>High risk</th>"
        "<th>Max risk</th><th>Top files</th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table>"
    )


def _metric_card(label: str, value: str) -> str:
    return f'<article class="metric"><span>{escape(label)}</span><strong>{escape(value)}</strong></article>'


def _risk_badge(score: int) -> str:
    band = risk_band(score)
    klass = {"high": "risk-high", "medium": "risk-med", "low": "risk-low"}[band]
    return f'<span class="risk {klass}" title="{band} risk">{escape(str(score))} {band}</span>'


MAX_DETAILED_FINDINGS = 300


def _safe_link(url: str) -> str:
    if not url.startswith(("https://", "http://")):
        return escape(url)
    return f'<a href="{escape(url, quote=True)}" rel="noopener noreferrer">{escape(url)}</a>'


def _render_finding(entry: TriageReportEntry) -> str:
    f = entry.finding
    loc = f.location.file_path or "(unknown file)"
    if f.location.start_line is not None:
        loc += f":{f.location.start_line}"
    if entry.triage.is_error:
        badge = '<span class="risk risk-err">error</span>'
    else:
        badge = _risk_badge(entry.triage.risk_score)
    card = entry.remediation
    parts = [
        '<details class="finding">',
        f"<summary>{badge} <strong>{escape(card.title if card and card.title else f.title or f.rule_id)}</strong>"
        f' <code class="muted">{escape(loc)}</code></summary>',
        '<div class="body">',
        f'<p class="muted">Rule <code>{escape(f.rule_id or f.id)}</code> · scanner severity {escape(f.severity or "-")}'
        + (f" · {escape(f.cve)}" if f.cve else "")
        + (f" · {escape(f.cwe)}" if f.cwe else "")
        + (f" · confidence {entry.triage.confidence}/10" if entry.triage.confidence is not None else "")
        + "</p>",
    ]
    if entry.triage.is_error:
        parts.append(f"<p>Triage failed: {escape(entry.triage.error or '')}</p>")
    if entry.triage.reasoning:
        parts.append(f"<h4>Why</h4><p>{escape(entry.triage.reasoning)}</p>")
    if entry.triage.exploitability_notes:
        parts.append(f"<h4>Exploitability</h4><p>{escape(entry.triage.exploitability_notes)}</p>")
    if card:
        if card.business_impact:
            parts.append(f"<h4>Business impact</h4><p>{escape(card.business_impact)}</p>")
        if card.steps:
            parts.append("<h4>Fix</h4><ol>" + "".join(f"<li>{escape(s)}</li>" for s in card.steps) + "</ol>")
        if card.code_snippet:
            parts.append(f"<pre><code>{escape(card.code_snippet)}</code></pre>")
        if card.reference_links:
            parts.append(
                "<h4>References</h4><ul>" + "".join(f"<li>{_safe_link(u)}</li>" for u in card.reference_links) + "</ul>"
            )
    parts.append("</div></details>")
    return "".join(parts)


def _render_findings_detail(report: TriageReport) -> str:
    shown = sorted(
        (e for e in report.entries if e.is_actionable or e.triage.is_error),
        key=lambda e: (not e.triage.is_error, -e.triage.risk_score, e.finding.id),
    )
    if not shown:
        return '<div class="empty">No actionable findings.</div>'
    extra = len(shown) - MAX_DETAILED_FINDINGS
    html_parts = [_render_finding(e) for e in shown[:MAX_DETAILED_FINDINGS]]
    if extra > 0:
        html_parts.append(f'<p class="muted">… and {extra} more (see the JSON report).</p>')
    return "".join(html_parts)


def _scanner_mix(source_formats: object) -> str:
    entries = source_formats.items() if isinstance(source_formats, dict) else []
    return ", ".join(f"{name}:{count}" for name, count in entries) or "-"


def _signed(value: int) -> str:
    return f"{value:+d}"
