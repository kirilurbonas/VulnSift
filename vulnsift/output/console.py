"""Rich CLI summary table and progress."""

from __future__ import annotations

from vulnsift.analytics import get_hotspots, get_priority_findings, summarize_report
from vulnsift.codeowners import CodeownersRule, summarize_by_owner
from vulnsift.models import TriageReport

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
except ImportError:
    Console = None  # type: ignore
    Table = None
    Progress = None
    Panel = None


def render_summary_table(
    report: TriageReport,
    *,
    include_false_positives: bool = False,
    console: Console | None = None,
) -> None:
    """
    Render a colour-coded summary table of triaged findings.
    By default excludes entries marked as likely false positive from the table.
    """
    if Console is None or Table is None:
        print("Rich not installed; skipping table.")
        return

    cons = console or Console()
    entries = report.entries
    if not include_false_positives:
        entries = [e for e in entries if not e.triage.is_likely_false_positive]
    entries = sorted(entries, key=lambda e: (-e.triage.risk_score, e.finding.id))

    table = Table(title="VulnSift Triage Summary", show_header=True, header_style="bold")
    table.add_column("Risk", justify="right", style="bold")
    table.add_column("ID", max_width=24)
    table.add_column("Title", max_width=50)
    table.add_column("FP?", justify="center")
    table.add_column("Location")

    for e in entries:
        risk = str(e.triage.risk_score)
        if e.triage.risk_score >= 7:
            risk_style = "red bold"
        elif e.triage.risk_score >= 4:
            risk_style = "yellow"
        else:
            risk_style = "green"
        fp = "Yes" if e.triage.is_likely_false_positive else "No"
        loc = e.finding.location.file_path or "-"
        if e.finding.location.start_line is not None:
            loc = f"{loc}:{e.finding.location.start_line}"
        table.add_row(
            f"[{risk_style}]{risk}[/]",
            e.finding.id[:24] if e.finding.id else "-",
            (e.finding.title or "-")[:50],
            fp,
            loc[:40] + "..." if len(loc) > 40 else loc,
        )

    cons.print(table)


def render_report_insights(report: TriageReport, *, top_n: int = 5, console: Console | None = None) -> None:
    """Render a compact overview plus hotspots and immediate priorities."""
    if Console is None or Table is None:
        return

    cons = console or Console()
    summary = summarize_report(report)
    risk_bands = summary["risk_bands"]
    source_formats = summary["source_formats"]

    overview = Table(title="Overview", show_header=False, box=None, pad_edge=False)
    overview.add_column("Metric", style="bold cyan")
    overview.add_column("Value")
    overview.add_row("Actionable findings", str(summary["actionable_findings"]))
    overview.add_row("Likely false positives", str(summary["false_positives"]))
    overview.add_row("Highest risk", str(summary["highest_risk"]))
    overview.add_row("Average actionable risk", str(summary["average_risk"]))
    overview.add_row(
        "Risk distribution",
        f"high {risk_bands['high']}  medium {risk_bands['medium']}  low {risk_bands['low']}",
    )
    overview.add_row(
        "Scanner mix",
        ", ".join(f"{name}:{count}" for name, count in source_formats.items()) or "-",
    )
    if Panel is not None:
        cons.print(Panel(overview, border_style="cyan", expand=False))
    else:
        cons.print(overview)

    hotspots = get_hotspots(report, limit=top_n)
    if hotspots:
        table = Table(title="Hotspots", show_header=True, header_style="bold")
        table.add_column("File", max_width=46)
        table.add_column("Findings", justify="right")
        table.add_column("High", justify="right")
        table.add_column("Max", justify="right")
        table.add_column("Avg", justify="right")
        table.add_column("Rules", max_width=28)
        for hotspot in hotspots:
            table.add_row(
                _truncate(str(hotspot["file_path"]), 46),
                str(hotspot["finding_count"]),
                str(hotspot["high_risk_count"]),
                str(hotspot["max_risk"]),
                str(hotspot["avg_risk"]),
                ", ".join(hotspot["top_rule_ids"]) or "-",
            )
        cons.print(table)

    priorities = get_priority_findings(report, limit=top_n)
    if priorities:
        table = Table(title="Immediate Priorities", show_header=True, header_style="bold")
        table.add_column("Risk", justify="right")
        table.add_column("Rule", max_width=24)
        table.add_column("File", max_width=38)
        table.add_column("Fix", max_width=34)
        for item in priorities:
            fix_title = item["remediation_title"] or "Review manually"
            line = f":{item['line']}" if item["line"] else ""
            table.add_row(
                _risk_markup(int(item["risk_score"])),
                _truncate(str(item["rule_id"]), 24),
                _truncate(f"{item['file_path']}{line}", 38),
                _truncate(str(fix_title), 34),
            )
        cons.print(table)


def render_comparison_summary(
    comparison: dict[str, object],
    *,
    top_n: int = 5,
    console: Console | None = None,
) -> None:
    """Render a baseline comparison with regressions and progress."""
    if Console is None or Table is None:
        return

    cons = console or Console()
    summary = comparison["summary"]
    trend = comparison["trend"]
    trend_style = {"improved": "green", "worsened": "red", "stable": "yellow"}.get(str(trend), "white")

    overview = Table(title="Baseline Comparison", show_header=False, box=None, pad_edge=False)
    overview.add_column("Metric", style="bold cyan")
    overview.add_column("Value")
    overview.add_row("Trend", f"[{trend_style} bold]{str(trend).upper()}[/]")
    overview.add_row("Actionable delta", _signed(int(summary["actionable_delta"])))
    overview.add_row("Total risk delta", _signed(int(summary["risk_delta"])))
    overview.add_row("Max risk delta", _signed(int(summary["max_risk_delta"])))
    overview.add_row("New actionable", str(summary["new_actionable"]))
    overview.add_row("Resolved actionable", str(summary["resolved_actionable"]))
    overview.add_row("New high risk", str(summary["new_high_risk"]))
    overview.add_row("Resolved high risk", str(summary["resolved_high_risk"]))
    if Panel is not None:
        cons.print(Panel(overview, border_style=trend_style, expand=False))
    else:
        cons.print(overview)

    _render_change_table(
        cons,
        title="New Findings",
        items=comparison["new_findings"],
        top_n=top_n,
        empty_message="No new actionable findings compared with the baseline.",
    )
    _render_change_table(
        cons,
        title="Resolved Findings",
        items=comparison["resolved_findings"],
        top_n=top_n,
        empty_message="No actionable findings were resolved compared with the baseline.",
    )

    escalated = comparison["escalated_findings"]
    if escalated:
        table = Table(title="Escalated Findings", show_header=True, header_style="bold")
        table.add_column("Delta", justify="right")
        table.add_column("Current", justify="right")
        table.add_column("Rule", max_width=24)
        table.add_column("File", max_width=42)
        for item in list(escalated)[: max(top_n, 0)]:
            line = f":{item['line']}" if item["line"] else ""
            table.add_row(
                _signed(int(item["risk_delta"])),
                str(item["risk_score"]),
                _truncate(str(item["rule_id"]), 24),
                _truncate(f"{item['file_path']}{line}", 42),
            )
        cons.print(table)


def render_owner_summary_table(
    report: TriageReport,
    rules: list[CodeownersRule],
    *,
    top_n: int = 10,
    min_risk: float = 0,
    unowned_label: str = "(unowned)",
    console: Console | None = None,
) -> None:
    """Render owner rollups from CODEOWNERS."""
    if Console is None or Table is None:
        return

    cons = console or Console()
    rows = summarize_by_owner(
        report,
        rules,
        min_risk=min_risk,
        limit=top_n,
        unowned_label=unowned_label,
    )
    if not rows:
        cons.print("[dim]No actionable findings matched the owner summary filters.[/]")
        return

    table = Table(title="Owner Summary", show_header=True, header_style="bold")
    table.add_column("Owners", max_width=34)
    table.add_column("Findings", justify="right")
    table.add_column("High", justify="right")
    table.add_column("Max", justify="right")
    table.add_column("Avg", justify="right")
    table.add_column("Top Files", max_width=40)
    for row in rows:
        table.add_row(
            _truncate(str(row["owners"]), 34),
            str(row["finding_count"]),
            str(row["high_risk_count"]),
            _risk_markup(int(row["max_risk"])),
            str(row["avg_risk"]),
            _truncate(", ".join(str(item) for item in row["top_files"]) or "-", 40),
        )
    cons.print(table)


def progress_spinner(console: Console | None = None):
    """Context manager for a Rich progress spinner (e.g. during triage)."""
    if Progress is None:
        return _noop_context()
    cons = console or Console()
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=cons,
    )


class _noop_context:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def add_task(self, *args, **kwargs):
        return None

    def advance(self, task_id, advance=1):
        pass


def _render_change_table(
    console: Console,
    *,
    title: str,
    items: object,
    top_n: int,
    empty_message: str,
) -> None:
    rows = list(items)
    if not rows:
        console.print(f"[dim]{empty_message}[/]")
        return
    table = Table(title=title, show_header=True, header_style="bold")
    table.add_column("Risk", justify="right")
    table.add_column("Rule", max_width=24)
    table.add_column("File", max_width=42)
    table.add_column("Fix", max_width=28)
    for item in rows[: max(top_n, 0)]:
        line = f":{item['line']}" if item["line"] else ""
        table.add_row(
            _risk_markup(int(item["risk_score"])),
            _truncate(str(item["rule_id"]), 24),
            _truncate(f"{item['file_path']}{line}", 42),
            _truncate(str(item["remediation_title"] or "-"), 28),
        )
    console.print(table)


def _risk_markup(score: int) -> str:
    if score >= 7:
        return f"[red bold]{score}[/]"
    if score >= 4:
        return f"[yellow]{score}[/]"
    return f"[green]{score}[/]"


def _truncate(value: str, length: int) -> str:
    if len(value) <= length:
        return value
    if length <= 3:
        return value[:length]
    return value[: length - 3] + "..."


def _signed(value: int) -> str:
    return f"{value:+d}"
