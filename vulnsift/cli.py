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

from vulnsift import __version__
from vulnsift.analytics import compare_reports
from vulnsift.codeowners import load_codeowners
from vulnsift.config import VulnSiftConfig, load_config, resolve_anthropic_api_key
from vulnsift.models import TriageReport, TriageReportEntry, TriageResult
from vulnsift.output import (
    export_report_json,
    render_backlog,
    render_comparison_summary,
    render_html_report,
    render_owner_summary,
    render_owner_summary_table,
    render_remediation_cards,
    render_remediation_cards_single,
    render_report_insights,
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


def _require_api_key(cfg: VulnSiftConfig | None = None) -> None:
    """
    Ensure ANTHROPIC_API_KEY is available (env or api_key_file in config) before API calls.
    """
    cfg = cfg or load_config()
    key = resolve_anthropic_api_key(cfg)
    if not key:
        _err_with_hint(
            "ANTHROPIC_API_KEY is not set and api_key_file could not be read.",
            "Set ANTHROPIC_API_KEY, add it to .env, or set api_key_file in vulnsift.yaml to a file containing the key.",
        )
    os.environ["ANTHROPIC_API_KEY"] = key


def _load_triage_report(path_like: str) -> TriageReport:
    path = Path(path_like)
    if path.suffix.lower() != ".json":
        _err_with_hint("Expected a JSON file (e.g. triage-report.json).")
    try:
        return TriageReport.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as e:
        _err_with_hint(str(e), "Tip: generate with `vulnsift triage --input <scan> --export json`.")
    raise AssertionError("unreachable")


def _load_codeowners_rules(
    path_like: str | None,
    *,
    required: bool = False,
) -> tuple[list, Path | None]:
    try:
        rules, resolved = load_codeowners(path_like, cwd=Path.cwd())
    except FileNotFoundError as e:
        _err_with_hint(str(e), "Provide --codeowners <path> or add a standard CODEOWNERS file to the repo.")

    if required and resolved is None:
        _err_with_hint(
            "Could not find a CODEOWNERS file.",
            "Add .github/CODEOWNERS, CODEOWNERS, or pass --codeowners <path>.",
        )

    return rules, resolved


@click.group(
    epilog="""
Exit codes:  0 = success,  1 = error,  2 = triage gate failed (--gate-threshold).
""",
)
@click.version_option(version=__version__, prog_name="vulnsift")
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
@click.option("--seed", type=int, default=None, help="Random seed for --sample (reproducible CI runs).")
@click.option(
    "--cache",
    "cache_path",
    type=click.Path(),
    default=None,
    help="JSON cache file to reuse triage results for unchanged findings (invalidated when prompt_version changes).",
)
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
    seed: int | None,
    cache_path: str | None,
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
        if seed is not None:
            random.seed(seed)
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
    _require_api_key(cfg)

    from vulnsift.triage import cache as triage_cache

    cache_file = Path(cache_path) if cache_path else None
    cache_map: dict[str, dict] = {}
    if cache_file:
        cache_map = triage_cache.load_cache(cache_file, PROMPT_VERSION)

    report = TriageReport(source_file=str(input_path), prompt_version=PROMPT_VERSION, entries=[])
    out_dir.mkdir(parents=True, exist_ok=True)

    with progress_spinner(console) as progress:
        task = progress.add_task("Triaging findings...", total=len(findings)) if progress else None
        for f in findings:
            fp = triage_cache.fingerprint(f, PROMPT_VERSION, redact_code)
            if cache_file and fp in cache_map:
                cached_entry = triage_cache.cache_entry_to_report_entry(f, cache_map[fp])
                if cached_entry is not None:
                    report.entries.append(cached_entry)
                    if verbose:
                        console.print(f"[dim]Cache hit {f.id}[/]")
                    if task is not None:
                        progress.advance(task)
                    continue
            try:
                triage_result, remediation = triage_finding(f, project_context=context, redact_code=redact_code)
                entry = TriageReportEntry(finding=f, triage=triage_result, remediation=remediation)
                report.entries.append(entry)
                if cache_file:
                    cache_map[fp] = triage_cache.report_entry_to_cache_dict(entry)
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

    if cache_file:
        triage_cache.save_cache(cache_file, cache_map, PROMPT_VERSION)
        if verbose:
            console.print(f"[dim]Wrote triage cache to {cache_file}[/]")

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
  vulnsift report --input ./out/current.json --baseline ./out/previous.json
""",
)
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Triage report JSON file.")
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True),
    default=None,
    help="Optional baseline triage report to compare against.",
)
@click.option("--top", type=int, default=5, show_default=True, help="How many hotspots/priorities to display.")
def report(input_path: str, baseline_path: str | None, top: int) -> None:
    """Summarize a previously exported triage report (JSON)."""
    report_obj = _load_triage_report(input_path)
    render_summary_table(report_obj, include_false_positives=True, console=console)
    render_report_insights(report_obj, top_n=top, console=console)
    if baseline_path:
        baseline_report = _load_triage_report(baseline_path)
        comparison = compare_reports(report_obj, baseline_report)
        render_comparison_summary(comparison, top_n=top, console=console)


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
  vulnsift compare --current ./out/current.json --baseline ./out/previous.json
  vulnsift compare --current report.json --baseline baseline.json --fail-on-new-risk 7
""",
)
@click.option("--current", "current_path", required=True, type=click.Path(exists=True), help="Current triage report.")
@click.option(
    "--baseline",
    "baseline_path",
    required=True,
    type=click.Path(exists=True),
    help="Baseline triage report.",
)
@click.option("--top", type=int, default=5, show_default=True, help="How many findings to show per comparison section.")
@click.option(
    "--fail-on-new-risk",
    type=float,
    default=None,
    help="Exit with code 2 if any new actionable finding has risk >= this threshold.",
)
def compare(current_path: str, baseline_path: str, top: int, fail_on_new_risk: float | None) -> None:
    """Compare two triage reports to spot regressions, fixes, and risk movement."""
    current_report = _load_triage_report(current_path)
    baseline_report = _load_triage_report(baseline_path)

    comparison = compare_reports(current_report, baseline_report)
    render_comparison_summary(comparison, top_n=top, console=console)

    if fail_on_new_risk is not None:
        new_findings = comparison["new_findings"]
        new_high_risk = [
            item for item in new_findings if float(item["risk_score"]) >= float(fail_on_new_risk)
        ]
        if new_high_risk:
            console.print(
                f"[red]Regression gate failed:[/] {len(new_high_risk)} new actionable finding(s) "
                f"with risk >= {fail_on_new_risk}."
            )
            raise SystemExit(2)


@main.command(
    epilog="""
Examples:
  vulnsift share --input ./out/triage-report.json --output ./out/triage-report.html
  vulnsift share --input current.json --baseline previous.json --output comparison.html
""",
)
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Triage report JSON file.")
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True),
    default=None,
    help="Optional baseline triage report to include comparison insights.",
)
@click.option("--output", "output_path", required=True, type=click.Path(), help="HTML file to write.")
@click.option("--title", default=None, help="Optional page title for the shared report.")
@click.option("--top", type=int, default=10, show_default=True, help="How many hotspots and findings to display.")
@click.option(
    "--codeowners",
    "codeowners_path",
    type=click.Path(exists=True),
    default=None,
    help="Optional CODEOWNERS file to add owner rollups to the report.",
)
@click.option(
    "--unowned-label",
    default="(unowned)",
    show_default=True,
    help="Label to use when no CODEOWNERS rule matches a finding.",
)
def share(
    input_path: str,
    baseline_path: str | None,
    output_path: str,
    title: str | None,
    top: int,
    codeowners_path: str | None,
    unowned_label: str,
) -> None:
    """Write a standalone HTML report artifact for sharing triage results."""
    report_obj = _load_triage_report(input_path)
    baseline_report = _load_triage_report(baseline_path) if baseline_path else None
    owner_rules, owner_source = _load_codeowners_rules(codeowners_path, required=False)

    html = render_html_report(
        report_obj,
        baseline=baseline_report,
        title=title,
        top_n=top,
        owner_rules=owner_rules or None,
        unowned_label=unowned_label,
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
    console.print(f"[green]Wrote standalone HTML report to {output}[/]")
    if owner_source is not None:
        console.print(f"[dim]Included CODEOWNERS ownership from {owner_source}[/]")


@main.command(
    epilog="""
Examples:
  vulnsift backlog --input ./out/triage-report.json --format csv --output ./out/backlog.csv
  vulnsift backlog --input ./out/triage-report.json --format md --top 15
""",
)
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Triage report JSON file.")
@click.option(
    "--format",
    "export_format",
    type=click.Choice(["csv", "json", "md"]),
    default="csv",
    show_default=True,
    help="Backlog export format.",
)
@click.option("--output", "output_path", type=click.Path(), default=None, help="Optional file path to write.")
@click.option("--min-risk", type=float, default=4.0, show_default=True, help="Minimum risk score to include.")
@click.option("--top", type=int, default=25, show_default=True, help="How many backlog items to include.")
@click.option(
    "--codeowners",
    "codeowners_path",
    type=click.Path(exists=True),
    default=None,
    help="Optional CODEOWNERS file to annotate backlog items with owners.",
)
@click.option(
    "--unowned-label",
    default="(unowned)",
    show_default=True,
    help="Label to use when no CODEOWNERS rule matches a finding.",
)
def backlog(
    input_path: str,
    export_format: str,
    output_path: str | None,
    min_risk: float,
    top: int,
    codeowners_path: str | None,
    unowned_label: str,
) -> None:
    """Export a prioritized remediation backlog from a triage report."""
    report_obj = _load_triage_report(input_path)
    owner_rules, owner_source = _load_codeowners_rules(codeowners_path, required=False)
    rendered = render_backlog(
        report_obj,
        export_format=export_format,
        top=top,
        min_risk=min_risk,
        owner_rules=owner_rules or None,
        unowned_label=unowned_label,
    )
    if output_path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Wrote prioritized backlog to {output}[/]")
        if owner_source is not None:
            console.print(f"[dim]Annotated backlog with CODEOWNERS from {owner_source}[/]")
    else:
        click.echo(rendered)


@main.command(
    epilog="""
Examples:
  vulnsift owners --input ./out/triage-report.json
  vulnsift owners --input ./out/triage-report.json --format csv --output ./out/owners.csv
""",
)
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Triage report JSON file.")
@click.option(
    "--codeowners",
    "codeowners_path",
    type=click.Path(exists=True),
    default=None,
    help="CODEOWNERS file to use. Defaults to the standard repo locations if omitted.",
)
@click.option(
    "--format",
    "export_format",
    type=click.Choice(["table", "json", "csv", "md"]),
    default="table",
    show_default=True,
    help="Owner summary output format.",
)
@click.option("--output", "output_path", type=click.Path(), default=None, help="Optional file path to write.")
@click.option("--min-risk", type=float, default=0.0, show_default=True, help="Minimum risk score to include.")
@click.option("--top", type=int, default=15, show_default=True, help="How many owner rows to include.")
@click.option(
    "--unowned-label",
    default="(unowned)",
    show_default=True,
    help="Label to use when no CODEOWNERS rule matches a finding.",
)
def owners(
    input_path: str,
    codeowners_path: str | None,
    export_format: str,
    output_path: str | None,
    min_risk: float,
    top: int,
    unowned_label: str,
) -> None:
    """Summarize actionable findings by CODEOWNERS ownership."""
    report_obj = _load_triage_report(input_path)
    rules, resolved = _load_codeowners_rules(codeowners_path, required=True)
    assert resolved is not None

    if output_path and export_format == "table":
        _err_with_hint("The 'table' format writes to stdout only.", "Use --format csv|json|md with --output.")

    if export_format == "table":
        console.print(f"[dim]Using CODEOWNERS from {resolved}[/]")
        render_owner_summary_table(
            report_obj,
            rules,
            top_n=top,
            min_risk=min_risk,
            unowned_label=unowned_label,
            console=console,
        )
        return

    rendered = render_owner_summary(
        report_obj,
        rules,
        export_format=export_format,
        min_risk=min_risk,
        top=top,
        unowned_label=unowned_label,
    )
    if output_path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]Wrote owner summary to {output}[/]")
    else:
        click.echo(rendered)


@main.command(
    epilog="""
Examples:
  vulnsift autofix --input vulnsift-output/triage-report.json --dry-run
  vulnsift autofix --input report.json --list-only
  vulnsift autofix --input report.json --min-risk 8 --max-fixes 3
  vulnsift autofix --input report.json --open-pr

Note: --dry-run still calls the Anthropic API to generate patches; it only skips writing files/PRs.
Use --list-only to print eligible findings without any API calls.
""",
)
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Triage report JSON file.")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Call API to generate patches and print diffs; do not modify files or create PRs.",
)
@click.option(
    "--list-only",
    is_flag=True,
    help="Print eligible findings (no API calls, no disk writes).",
)
@click.option("--min-risk", type=float, default=7.0, help="Minimum risk score to attempt auto-fix (default: 7).")
@click.option("--max-fixes", type=int, default=None, help="Cap how many findings to send to the model (order: report).")
@click.option("--repo-root", type=click.Path(exists=True), default=".", help="Repository root (default: current dir).")
@click.option("--open-pr", is_flag=True, help="Create a GitHub PR for each fix (requires gh CLI).")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
def autofix(
    input_path: str,
    dry_run: bool,
    list_only: bool,
    min_risk: float,
    max_fixes: int | None,
    repo_root: str,
    open_pr: bool,
    verbose: bool,
) -> None:
    """Generate AI-powered code patches for high-risk findings (sends source code to the model)."""
    from vulnsift.autofix.agent import autofix_report as run_autofix
    from vulnsift.autofix.patches import generate_diff

    report_obj = _load_triage_report(input_path)

    cfg = load_config()
    root = Path(repo_root).resolve()

    if list_only:
        from vulnsift.autofix.agent import _filter_eligible

        eligible = _filter_eligible(report_obj.entries, min_risk)
        if max_fixes is not None and max_fixes > 0:
            eligible = eligible[:max_fixes]
        if not eligible:
            console.print("[yellow]No eligible findings for auto-fix at this min-risk.[/]")
            return
        console.print(f"[dim]{len(eligible)} eligible finding(s) (no API calls):[/]")
        for e in eligible:
            console.print(
                f"  - [bold]{e.finding.id}[/] risk={e.triage.risk_score} "
                f"{e.finding.location.file_path}:{e.finding.location.start_line or '?'}"
            )
        return

    if not dry_run:
        _require_api_key(cfg)

    console.print(f"[dim]Auto-fixing findings with risk >= {min_risk} in {root}[/]")
    console.print(
        "[dim]Autofix sends finding metadata and full source files to the Anthropic API.[/]"
    )

    if dry_run:
        _require_api_key(cfg)

    results = run_autofix(report_obj, root, dry_run=dry_run, min_risk=min_risk, max_fixes=max_fixes)

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

    report_obj = _load_triage_report(input_path)
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

    report_obj = _load_triage_report(input_path)

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
