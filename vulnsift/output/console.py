"""Rich CLI summary table and progress."""

from __future__ import annotations

from vulnsift.models import TriageReport

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
except ImportError:
    Console = None  # type: ignore
    Table = None
    Progress = None


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
