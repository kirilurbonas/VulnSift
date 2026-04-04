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
from vulnsift.triage.prompts import PROMPT_VERSION

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
  vulnsift triage --input scan.sarif --redact-code --gate-threshold 7
  vulnsift triage --input scan.sarif --sample 50
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
@click.option("--limit", type=int, default=None, help="Max number of findings to triage (first N).")
@click.option("--sample", type=int, default=None, help="Randomly sample N findings to triage (instead of all/first N).")
@click.option("--dry-run", is_flag=True, help="Parse and validate only; do not call triage API.")
@click.option("--redact-code", is_flag=True, help="Do not send code snippets to the AI model.")
@click.option(
    "--gate-threshold",
    type=float,
    default=None,
    help="If set, exit with code 2 when any non-FP finding has risk >= threshold.",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
def triage(
    input_path: str,
    fmt: str,
    export_format: str | None,
    output_dir: str | None,
    context: str | None,
    include_fp: bool,
    limit: int | None,
    sample: int | None,
    dry_run: bool,
    redact_code: bool,
    gate_threshold: float | None,
    verbose: bool,
) -> None:
    """Triage scan findings with Claude and output summary + remediation cards."""
    cfg = load_config()
    out_dir = Path(output_dir or cfg.output_dir)
    context = context or cfg.project_context
    redact_code = redact_code or cfg.redact_code
    gate_threshold = gate_threshold if gate_threshold is not None else cfg.gate_threshold

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

    total_findings = len(findings)
    if total_findings > 1000:
        console.print(
            f"[dim]Large scan ({total_findings} findings). Consider --limit or --sample to reduce cost.[/]"
        )

    if sample is not None and sample > 0:
        import random
        n = min(sample, len(findings))
        findings = random.sample(findings, n)
        if verbose:
            console.print(f"[dim]Sampled {n} finding(s) at random[/]")
    if limit is not None and limit > 0:
        findings = findings[:limit]
        if verbose:
            console.print(f"[dim]Limited to {limit} finding(s)[/]")

    if dry_run:
        console.print(f"[green]Dry run:[/] Would triage [bold]{len(findings)}[/] finding(s).")
        return

    # Require API key only when we are about to make real triage calls.
    _require_api_key()

    report = TriageReport(source_file=str(input_path), prompt_version=PROMPT_VERSION, entries=[])
    out_dir.mkdir(parents=True, exist_ok=True)

    with progress_spinner(console) as progress:
        task = progress.add_task("Triaging findings...", total=len(findings)) if progress else None
        for f in findings:
            try:
                triage_result, remediation = triage_finding(f, project_context=context, redact_code=redact_code)
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

    # If gate_threshold is set, treat high-risk findings as a CI gate.
    if gate_threshold is not None:
        max_risk = max(
            (e.triage.risk_score for e in report.entries if not e.triage.is_likely_false_positive),
            default=0,
        )
        if max_risk >= gate_threshold:
            console.print(
                f"[red]Gate failed:[/] highest non-FP risk score {max_risk} >= threshold {gate_threshold}."
            )
            raise SystemExit(2)

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


@main.command(
    epilog="""
Examples:
  vulnsift autofix --input vulnsift-output/triage-report.json --dry-run
  vulnsift autofix --input report.json --min-risk 8
  vulnsift autofix --input report.json --open-pr
""",
)
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Triage report JSON file.")
@click.option("--dry-run", is_flag=True, help="Show diffs without modifying files or creating PRs.")
@click.option("--min-risk", type=float, default=7.0, help="Minimum risk score to attempt auto-fix (default: 7).")
@click.option("--repo-root", type=click.Path(exists=True), default=".", help="Repository root (default: current dir).")
@click.option("--open-pr", is_flag=True, help="Create a GitHub PR for each fix (requires gh CLI).")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
def autofix(
    input_path: str,
    dry_run: bool,
    min_risk: float,
    repo_root: str,
    open_pr: bool,
    verbose: bool,
) -> None:
    """Generate AI-powered code patches for high-risk findings."""
    from vulnsift.autofix.agent import autofix_report as run_autofix
    from vulnsift.autofix.patches import generate_diff

    path = Path(input_path)
    if path.suffix.lower() != ".json":
        _err_with_hint("Expected a JSON file (e.g. triage-report.json).")
    try:
        report_obj = TriageReport.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as e:
        _err_with_hint(str(e), "Tip: generate with `vulnsift triage --input <scan> --export json`.")

    if not dry_run:
        _require_api_key()

    root = Path(repo_root).resolve()
    console.print(f"[dim]Auto-fixing findings with risk >= {min_risk} in {root}[/]")

    if dry_run:
        # In dry-run mode, we still call the API to generate patches but don't apply them
        _require_api_key()

    results = run_autofix(report_obj, root, dry_run=dry_run, min_risk=min_risk)

    if not results:
        console.print("[yellow]No eligible findings to auto-fix.[/]")
        return

    for r in results:
        confidence_color = "green" if r.confidence >= 7 else "yellow" if r.confidence >= 4 else "red"
        console.print(
            f"\n[bold]{r.finding_id}[/] ({r.file_path}) "
            f"— confidence [{confidence_color}]{r.confidence}/10[/]"
        )
        console.print(f"  {r.explanation}")

        if dry_run:
            diff = generate_diff(Path(r.file_path), r.original_snippet, r.patched_snippet)
            if diff:
                console.print(f"[dim]{diff}[/]")
        elif r.applied:
            console.print(f"  [green]Patch applied to {r.file_path}[/]")

    applied = [r for r in results if r.applied]
    skipped = [r for r in results if not r.applied and not dry_run]

    if dry_run:
        console.print(f"\n[dim]Dry run: {len(results)} patch(es) generated, none applied.[/]")
    else:
        console.print(f"\n[green]{len(applied)} patch(es) applied[/]", end="")
        if skipped:
            console.print(f", [yellow]{len(skipped)} skipped (low confidence or validation errors)[/]")
        else:
            console.print()

    if open_pr and applied and not dry_run:
        from vulnsift.autofix.github_pr import commit_and_push, create_fix_branch, get_current_branch, open_pull_request

        base_branch = get_current_branch(root)
        for r in applied:
            try:
                branch = create_fix_branch(root, r.finding_id)
                commit_and_push(root, [root / r.file_path], f"fix: {r.explanation[:72]}")
                pr_url = open_pull_request(
                    root,
                    title=f"fix: auto-remediate {r.finding_id}",
                    body=(
                        f"## Auto-fix by VulnSift\n\n"
                        f"**Finding:** {r.finding_id}\n"
                        f"**File:** {r.file_path}\n"
                        f"**Confidence:** {r.confidence}/10\n\n"
                        f"{r.explanation}\n\n"
                        f"---\n*Generated by [VulnSift](https://github.com/kirilurbonas/VulnSift)*"
                    ),
                    base=base_branch,
                    head=branch,
                )
                console.print(f"  [green]PR created: {pr_url}[/]")
            except Exception as e:
                console.print(f"  [red]Failed to create PR for {r.finding_id}: {e}[/]")


@main.command(
    "github-comment",
    epilog="""
Examples:
  vulnsift github-comment --input vulnsift-output/triage-report.json
  vulnsift github-comment --input report.json --threshold 7 --output comment.md
""",
)
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Triage report JSON file.")
@click.option("--threshold", type=float, default=None, help="Gate threshold to display pass/fail badge.")
@click.option(
    "--output", "output_path", type=click.Path(), default=None, help="Write comment to file (default: stdout).",
)
def github_comment(input_path: str, threshold: float | None, output_path: str | None) -> None:
    """Render a GitHub PR comment from a triage report."""
    from vulnsift.output.github_comment import render_github_comment

    path = Path(input_path)
    if path.suffix.lower() != ".json":
        _err_with_hint("Expected a JSON file (e.g. triage-report.json).")
    try:
        report_obj = TriageReport.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as e:
        _err_with_hint(str(e), "Tip: generate with `vulnsift triage --input <scan> --export json`.")
    md = render_github_comment(report_obj, threshold=threshold)
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        console.print(f"[green]Wrote PR comment to {out}[/]")
    else:
        click.echo(md)


@main.command(
    epilog="""
Examples:
  vulnsift store --input vulnsift-output/triage-report.json
  vulnsift store --input report.json --db-path ./my-dashboard.db
""",
)
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Triage report JSON file.")
@click.option("--db-path", type=click.Path(), default=None, help="Dashboard DB path (~/.vulnsift/dashboard.db).")
def store(input_path: str, db_path: str | None) -> None:
    """Store a triage report in the dashboard database."""
    from vulnsift.dashboard.db import init_db, store_report

    path = Path(input_path)
    if path.suffix.lower() != ".json":
        _err_with_hint("Expected a JSON file (e.g. triage-report.json).")
    try:
        report_obj = TriageReport.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as e:
        _err_with_hint(str(e), "Tip: generate with `vulnsift triage --input <scan> --export json`.")

    conn = init_db(db_path) if db_path else init_db()
    scan_id = store_report(conn, report_obj)
    conn.close()
    console.print(f"[green]Stored report as scan #{scan_id}[/]")


@main.command(
    epilog="""
Examples:
  vulnsift dashboard
  vulnsift dashboard --port 9090
  vulnsift dashboard --db-path ./my-dashboard.db
""",
)
@click.option("--port", type=int, default=8080, help="Port to serve on (default: 8080).")
@click.option("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1).")
@click.option("--db-path", type=click.Path(), default=None, help="Dashboard DB path (~/.vulnsift/dashboard.db).")
def dashboard(port: int, host: str, db_path: str | None) -> None:
    """Launch the VulnSift web dashboard."""
    try:
        from vulnsift.dashboard.app import create_app
    except ImportError:
        _err_with_hint(
            "Flask is required for the dashboard.",
            "Install with: pip install vulnsift[dashboard]",
        )

    app = create_app(db_path=db_path)
    console.print(f"[green]VulnSift dashboard running at http://{host}:{port}[/]")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
