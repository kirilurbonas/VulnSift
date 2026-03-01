"""VulnSift CLI: triage, report, validate."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from vulnsift.models import TriageReport, TriageReportEntry, TriageResult
from vulnsift.output import export_report_json, render_remediation_cards, render_summary_table
from vulnsift.output.console import progress_spinner
from vulnsift.parsers import parse_scan_file
from vulnsift.triage.agent import triage_finding

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="vulnsift")
def main() -> None:
    """VulnSift: AI-powered vulnerability triage from scanner output to actionable remediation."""


@main.command()
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Scan file (SARIF or Snyk).")
@click.option("--format", "fmt", type=click.Choice(["sarif", "snyk"]), default="sarif", help="Input format.")
@click.option("--export", "export_format", type=click.Choice(["json"]), default=None, help="Export report as JSON.")
@click.option("--output-dir", type=click.Path(), default="./vulnsift-output", help="Dir for Markdown cards and JSON.")
@click.option("--context", default=None, help="Project context (e.g. 'Python app, internal only').")
@click.option("--include-fp", is_flag=True, help="Include likely false positives in summary table.")
def triage(
    input_path: str,
    fmt: str,
    export_format: str | None,
    output_dir: str,
    context: str | None,
    include_fp: bool,
) -> None:
    """Triage scan findings with Claude and output summary + remediation cards."""
    try:
        findings = parse_scan_file(input_path, fmt)
    except (ValueError, FileNotFoundError) as e:
        console.print(f"[red]Error:[/] {e}")
        raise SystemExit(1) from e

    if not findings:
        console.print("[green]No findings in scan file.[/]")
        return

    report = TriageReport(source_file=str(input_path), entries=[])
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with progress_spinner(console) as progress:
        task = progress.add_task("Triaging findings...", total=len(findings)) if progress else None
        for f in findings:
            try:
                triage_result, remediation = triage_finding(f, project_context=context)
                report.entries.append(
                    TriageReportEntry(finding=f, triage=triage_result, remediation=remediation)
                )
            except Exception as e:
                console.print(f"[yellow]Skip {f.id}:[/] {e}")
                report.entries.append(
                    TriageReportEntry(
                        finding=f,
                        triage=TriageResult(
                            risk_score=0,
                            is_likely_false_positive=True,
                            reasoning=str(e),
                        ),
                        remediation=None,
                    )
                )
            if task is not None:
                progress.advance(task)

    # Sort by risk score descending
    report.entries.sort(key=lambda e: (-e.triage.risk_score, e.finding.id))

    render_summary_table(report, include_false_positives=include_fp, console=console)
    written_cards = render_remediation_cards(report.entries, out_dir, only_actionable=True)
    if written_cards:
        console.print(f"[green]Wrote {len(written_cards)} remediation card(s) to {out_dir}[/]")

    if export_format == "json":
        json_path = out_dir / "triage-report.json"
        export_report_json(report, json_path)
        console.print(f"[green]Exported full report to {json_path}[/]")


@main.command()
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Triage report JSON file.")
def report(input_path: str) -> None:
    """Summarize a previously exported triage report (JSON)."""
    path = Path(input_path)
    if not path.suffix.lower() == ".json":
        console.print("[red]Expected a JSON file (e.g. triage-report.json).[/]")
        raise SystemExit(1)
    try:
        report = TriageReport.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[red]Error loading report:[/] {e}")
        raise SystemExit(1) from e
    render_summary_table(report, include_false_positives=True, console=console)


@main.command()
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Scan file to validate.")
@click.option("--format", "fmt", type=click.Choice(["sarif", "snyk"]), default="sarif", help="Input format.")
def validate(input_path: str, fmt: str) -> None:
    """Validate and parse a scan file (no API calls)."""
    try:
        findings = parse_scan_file(input_path, fmt)
        console.print(f"[green]OK:[/] Parsed [bold]{len(findings)}[/] finding(s).")
        for f in findings[:5]:
            console.print(f"  - {f.rule_id}: {f.title[:60]}...")
        if len(findings) > 5:
            console.print(f"  ... and {len(findings) - 5} more.")
    except (ValueError, FileNotFoundError) as e:
        console.print(f"[red]Validation failed:[/] {e}")
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
