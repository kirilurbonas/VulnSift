"""VulnSift CLI: triage, report, validate."""

from __future__ import annotations

import os
from pathlib import Path

# Optional: load .env so ANTHROPIC_API_KEY can be set without exporting
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import click
from rich.console import Console

from vulnsift.config import load_config
from vulnsift.models import TriageReport, TriageReportEntry, TriageResult
from vulnsift.output import (
    export_report_json,
    render_remediation_cards,
    render_remediation_cards_single,
    render_summary_table,
)
from vulnsift.output.console import progress_spinner
from vulnsift.parsers import SUPPORTED_FORMATS, detect_format, parse_scan_file
from vulnsift.triage.agent import triage_finding

console = Console()


def _err_with_hint(msg: str, hint: str | None = None) -> None:
    console.print(f"[red]Error:[/] {msg}")
    if hint:
        console.print(f"[dim]{hint}[/]")
    raise SystemExit(1)


def _require_api_key() -> None:
    """
    Ensure ANTHROPIC_API_KEY is present before making triage API calls.
    Dry-run and validate flows do not require it.
    """
    if not os.getenv("ANTHROPIC_API_KEY"):
        _err_with_hint(
            "ANTHROPIC_API_KEY is not set.",
            "Set ANTHROPIC_API_KEY in your environment (or .env) before running `vulnsift triage`.",
        )


@click.group()
@click.version_option(version="0.1.0", prog_name="vulnsift")
def main() -> None:
    """VulnSift: AI-powered vulnerability triage from scanner output to actionable remediation."""


@main.command(
    epilog="""
Examples:
  vulnsift triage --input scan.sarif --export json
  vulnsift triage --input scan.sarif --dry-run
  vulnsift triage --input scan.sarif --limit 10 --output-dir ./out
""",
)
@click.option(
    "--input",
    "input_path",
    required=True,
    type=click.Path(exists=True),
    help="Scan file (SARIF, Snyk, Semgrep, Trivy).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice([*SUPPORTED_FORMATS, "auto"]),
    default="auto",
    help="Input format; 'auto' to detect from file.",
)
@click.option(
    "--export",
    "export_format",
    type=click.Choice(["json", "md", "md-single"]),
    default=None,
    help="Export report: json, md (per-file cards), or md-single (one file).",
)
@click.option(
    "--output-dir",
    type=click.Path(),
    default=None,
    help="Dir for Markdown/JSON (default: from config or ./vulnsift-output).",
)
@click.option("--context", default=None, help="Project context (e.g. 'Python app, internal only'). Overrides config.")
@click.option("--include-fp", is_flag=True, help="Include likely false positives in summary table.")
@click.option("--limit", type=int, default=None, help="Max number of findings to triage (for testing).")
@click.option("--dry-run", is_flag=True, help="Parse and validate only; do not call triage API.")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
def triage(
    input_path: str,
    fmt: str,
    export_format: str | None,
    output_dir: str | None,
    context: str | None,
    include_fp: bool,
    limit: int | None,
    dry_run: bool,
    verbose: bool,
) -> None:
    """Triage scan findings with Claude and output summary + remediation cards."""
    cfg = load_config()
    out_dir = Path(output_dir or cfg.output_dir)
    context = context or cfg.project_context

    try:
        findings = parse_scan_file(input_path, fmt)
    except (ValueError, FileNotFoundError) as e:
        _err_with_hint(
            str(e),
            "Tip: run `vulnsift validate --input <file> [--format auto]` to check the file.",
        )

    if verbose:
        console.print(f"[dim]Parsed {len(findings)} finding(s) from {input_path}[/]")
    if not findings:
        console.print("[green]No findings in scan file.[/]")
        return

    if limit is not None:
        findings = findings[:limit]
        if verbose:
            console.print(f"[dim]Limited to {limit} finding(s)[/]")

    if dry_run:
        console.print(f"[green]Dry run:[/] Would triage [bold]{len(findings)}[/] finding(s).")
        return

    # Require API key only when we are about to make real triage calls.
    _require_api_key()

    report = TriageReport(source_file=str(input_path), entries=[])
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
                if verbose:
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

    report.entries.sort(key=lambda e: (-e.triage.risk_score, e.finding.id))

    render_summary_table(report, include_false_positives=include_fp, console=console)
    written_cards = render_remediation_cards(report.entries, out_dir, only_actionable=True)
    if written_cards:
        console.print(f"[green]Wrote {len(written_cards)} remediation card(s) to {out_dir}[/]")

    if export_format == "json":
        json_path = out_dir / "triage-report.json"
        export_report_json(report, json_path)
        console.print(f"[green]Exported full report to {json_path}[/]")
    elif export_format == "md-single":
        single_path = out_dir / "remediation.md"
        render_remediation_cards_single(report.entries, single_path, only_actionable=True)
        console.print(f"[green]Exported single remediation file to {single_path}[/]")


@main.command(
    epilog="""
Examples:
  vulnsift report --input ./vulnsift-output/triage-report.json
""",
)
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Triage report JSON file.")
def report(input_path: str) -> None:
    """Summarize a previously exported triage report (JSON)."""
    path = Path(input_path)
    if path.suffix.lower() != ".json":
        _err_with_hint("Expected a JSON file (e.g. triage-report.json).")
    try:
        report_obj = TriageReport.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as e:
        _err_with_hint(str(e), "Tip: generate with `vulnsift triage --input <scan> --export json`.")
    render_summary_table(report_obj, include_false_positives=True, console=console)


@main.command(
    epilog="""
Examples:
  vulnsift validate --input scan.sarif
  vulnsift validate --input fixtures/sample.sarif.json --format auto
""",
)
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Scan file to validate.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice([*SUPPORTED_FORMATS, "auto"]),
    default="auto",
    help="Input format; 'auto' to detect.",
)
def validate(input_path: str, fmt: str) -> None:
    """Validate and parse a scan file (no API calls)."""
    try:
        if fmt == "auto":
            detected = detect_format(input_path)
            console.print(f"[dim]Detected format: {detected}[/]")
            fmt = detected
        findings = parse_scan_file(input_path, fmt)
        console.print(f"[green]OK:[/] Parsed [bold]{len(findings)}[/] finding(s).")
        for f in findings[:5]:
            title = (f.title[:60] + "...") if len(f.title) > 60 else f.title
            console.print(f"  - {f.rule_id}: {title}")
        if len(findings) > 5:
            console.print(f"  ... and {len(findings) - 5} more.")
    except (ValueError, FileNotFoundError) as e:
        _err_with_hint(str(e), "Use --format sarif|snyk|semgrep|trivy if auto-detection fails.")


if __name__ == "__main__":
    main()
