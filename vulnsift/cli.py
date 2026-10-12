"""VulnSift CLI: triage, report, compare, share, backlog, owners, autofix, dashboard."""

from __future__ import annotations

import os
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

import click
from rich.console import Console

from vulnsift import __version__
from vulnsift.analytics import compare_reports, evaluate_gate
from vulnsift.codeowners import load_codeowners
from vulnsift.config import ConfigError, VulnSiftConfig, load_config, resolve_anthropic_api_key
from vulnsift.models import TriageReport
from vulnsift.output import (
    export_report_json,
    export_report_sarif,
    progress_bar,
    render_backlog,
    render_comparison_summary,
    render_html_report,
    render_owner_summary,
    render_owner_summary_table,
    render_remediation_cards,
    render_remediation_cards_single,
    render_report_insights,
    render_summary_table,
    render_usage,
)
from vulnsift.parsers import SUPPORTED_FORMATS, detect_format, parse_scan_file
from vulnsift.triage.prompts import PROMPT_VERSION

console = Console()
err_console = Console(stderr=True)

EFFORT_LEVELS = ["low", "medium", "high", "xhigh", "max"]


def _err_with_hint(msg: str, hint: str | None = None, *, code: int = 1) -> NoReturn:
    err_console.print(f"[red]Error:[/] {msg}", highlight=False)
    if hint:
        err_console.print(f"[dim]{hint}[/]", highlight=False)
    raise SystemExit(code)


def _config() -> VulnSiftConfig:
    """Load config once per invocation (honours --config / VULNSIFT_CONFIG)."""
    ctx = click.get_current_context()
    root = ctx.find_root()
    root.ensure_object(dict)
    if "config" not in root.obj:
        try:
            root.obj["config"] = load_config(path=root.obj.get("config_path"))
        except ConfigError as e:
            _err_with_hint(str(e), "Fix the config file or point --config at another one.")
    return root.obj["config"]


def _require_api_key(cfg: VulnSiftConfig | None = None) -> str:
    """Ensure ANTHROPIC_API_KEY is available (env or api_key_file in config) before API calls."""
    cfg = cfg or _config()
    key = resolve_anthropic_api_key(cfg)
    if not key:
        _err_with_hint(
            "ANTHROPIC_API_KEY is not set and api_key_file could not be read.",
            "Set ANTHROPIC_API_KEY, add it to .env, or set api_key_file in vulnsift.yaml to a file containing the key.",
        )
    os.environ["ANTHROPIC_API_KEY"] = key
    return key


def _load_triage_report(path_like: str) -> TriageReport:
    path = Path(path_like)
    try:
        return TriageReport.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as e:
        _err_with_hint(
            f"{path}: not a valid VulnSift triage report ({type(e).__name__}).",
            "Tip: generate one with `vulnsift triage --input <scan> --export json`.",
        )
    raise AssertionError("unreachable")


def _write_or_echo(rendered: str, output_path: str | None, message: str) -> None:
    if output_path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[green]{message} {output}[/]")
    else:
        click.echo(rendered)


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
Exit codes:  0 = success,  1 = error,  2 = gate failed (--gate-threshold / --fail-on-new-risk),
             130 = interrupted.
""",
)
@click.version_option(version=__version__, prog_name="vulnsift")
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False),
    envvar="VULNSIFT_CONFIG",
    default=None,
    help="Config file (default: nearest vulnsift.yaml / .vulnsift.yaml up to the repo root).",
)
@click.pass_context
def main(ctx: click.Context, config_path: str | None) -> None:
    """VulnSift: AI-powered vulnerability triage from scanner output to actionable remediation."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path
    # Optional: load .env so ANTHROPIC_API_KEY can be set without exporting (never overrides real env vars).
    if not os.environ.get("VULNSIFT_DISABLE_DOTENV"):
        try:
            from dotenv import find_dotenv, load_dotenv

            load_dotenv(find_dotenv(usecwd=True), override=False)
        except ImportError:
            pass


@main.command(
    epilog="""
Examples:
  vulnsift triage --input scan.sarif --export json
  vulnsift triage --input scan.sarif --dry-run
  vulnsift triage --input scan.sarif --limit 10 --output-dir ./out
  vulnsift triage --input scan.sarif --redact-code --gate-threshold 7 --export json --export sarif
  vulnsift triage --input scan.sarif --sample 50 --seed 1 --cache .vulnsift-cache.json
  vulnsift triage --input scan.sarif --model claude-sonnet-5-5 --concurrency 16
""",
)
@click.option(
    "--input",
    "input_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
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
    "export_formats",
    type=click.Choice(["json", "sarif", "md", "md-single"]),
    multiple=True,
    help="Repeatable. json: triage-report.json, sarif: triage-report.sarif, md: one card per finding "
    "(default when no --export), md-single: remediation.md.",
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False),
    default=None,
    help="Dir for Markdown/JSON/SARIF (default: from config or ./vulnsift-output).",
)
@click.option("--context", default=None, help="Project context (e.g. 'Python app, internal only'). Overrides config.")
@click.option("--project", default=None, help="Project name recorded in the report (used by the dashboard).")
@click.option("--include-fp", is_flag=True, help="Include likely false positives in summary table.")
@click.option("--limit", type=click.IntRange(min=1), default=None, help="Max number of findings to triage (first N).")
@click.option("--sample", type=click.IntRange(min=1), default=None, help="Randomly sample N findings to triage.")
@click.option("--seed", type=int, default=None, help="Random seed for --sample (reproducible CI runs).")
@click.option(
    "--cache",
    "cache_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="JSON cache to reuse results for unchanged findings (keyed on content, prompt, model and context).",
)
@click.option("--model", default=None, help="Claude model ID (default: from config or claude-opus-5-5).")
@click.option("--effort", type=click.Choice(EFFORT_LEVELS), default=None, help="Reasoning effort for the model.")
@click.option(
    "--concurrency", type=click.IntRange(1, 64), default=None, help="Parallel triage requests (default: 8)."
)
@click.option("--dry-run", is_flag=True, help="Parse and validate only; do not call triage API.")
@click.option("--redact-code", is_flag=True, help="Do not send code snippets to the AI model.")
@click.option(
    "--gate-threshold",
    type=click.FloatRange(0, 10),
    default=None,
    help="Exit with code 2 when any actionable finding has risk >= threshold.",
)
@click.option(
    "--fail-on-error/--allow-errors",
    default=None,
    help="With a gate, also fail when findings could not be triaged (default: fail).",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output.")
def triage(
    input_path: str,
    fmt: str,
    export_formats: tuple[str, ...],
    output_dir: str | None,
    context: str | None,
    project: str | None,
    include_fp: bool,
    limit: int | None,
    sample: int | None,
    seed: int | None,
    cache_path: str | None,
    model: str | None,
    effort: str | None,
    concurrency: int | None,
    dry_run: bool,
    redact_code: bool,
    gate_threshold: float | None,
    fail_on_error: bool | None,
    verbose: bool,
) -> None:
    """Triage scan findings with Claude and output summary + remediation cards."""
    cfg = _config()
    out_dir = Path(output_dir or cfg.output_dir)
    context = context or cfg.project_context
    project = project or cfg.project
    redact_code = redact_code or cfg.redact_code
    gate_threshold = gate_threshold if gate_threshold is not None else cfg.gate_threshold
    fail_on_error = cfg.fail_on_error if fail_on_error is None else fail_on_error
    model = model or cfg.model
    effort = effort or cfg.effort
    concurrency = concurrency or cfg.concurrency
    cache_path = cache_path or cfg.cache

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
        findings = []

    total_findings = len(findings)
    if total_findings > 1000 and not (limit or sample):
        console.print(
            f"[dim]Large scan ({total_findings} findings). Consider --limit, --sample or --cache to reduce cost.[/]"
        )

    if sample is not None:
        n = min(sample, len(findings))
        findings = random.Random(seed).sample(findings, n)
        if verbose:
            console.print(f"[dim]Sampled {n} finding(s) at random[/]")
    if limit is not None:
        findings = findings[:limit]
        if verbose:
            console.print(f"[dim]Limited to {limit} finding(s)[/]")

    if dry_run:
        console.print(f"[green]Dry run:[/] Would triage [bold]{len(findings)}[/] finding(s) with {model}.")
        return

    report = TriageReport(
        source_file=str(input_path),
        prompt_version=PROMPT_VERSION,
        model=model,
        project=project,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        entries=[],
    )

    if findings:
        # Require API key only when we are about to make real triage calls.
        key = _require_api_key(cfg)
        from vulnsift.llm import UsageTracker, make_client
        from vulnsift.triage.engine import FatalTriageError, TriageOptions, run_triage

        tracker = UsageTracker(model)
        options = TriageOptions(
            model=model, effort=effort, project_context=context, redact_code=redact_code, concurrency=concurrency
        )
        try:
            with progress_bar(console) as progress:
                task = progress.add_task("Triaging", total=len(findings), detail="")
                counts = {"error": 0}

                def on_result(entry, status: str) -> None:
                    if status == "error":
                        counts["error"] += 1
                        if verbose:
                            progress.console.print(
                                f"[magenta]Error {entry.finding.id}:[/] {entry.triage.error}", highlight=False
                            )
                    detail = f"{counts['error']} error(s)" if counts["error"] else ""
                    progress.update(task, advance=1, detail=detail)

                entries, stats = run_triage(
                    findings,
                    client=make_client(key),
                    options=options,
                    tracker=tracker,
                    cache_path=Path(cache_path) if cache_path else None,
                    on_result=on_result,
                )
        except FatalTriageError as e:
            _err_with_hint(f"Triage aborted: {e}", "No findings were assessed; nothing was written.")
        except KeyboardInterrupt:
            err_console.print("[yellow]Interrupted.[/] Partial results were saved to the cache (if --cache is set).")
            raise SystemExit(130) from None

        report.entries = entries
        report.usage = tracker.summary()
        if verbose or stats.cache_hits or stats.duplicates:
            console.print(
                f"[dim]{stats.total} finding(s): {stats.api_calls} triaged via API, {stats.cache_hits} from cache, "
                f"{stats.duplicates} duplicate(s) reused.[/]"
            )

    report.entries.sort(key=lambda e: (-e.triage.risk_score, e.finding.id))

    render_summary_table(report, include_false_positives=include_fp, console=console)
    render_usage(report.usage, model=model, console=console)

    # Write every requested artifact BEFORE evaluating the gate, so CI always has a report to show.
    out_dir.mkdir(parents=True, exist_ok=True)
    exports = set(export_formats) or {"md"}
    if "md" in exports:
        written_cards = render_remediation_cards(report.entries, out_dir, only_actionable=True)
        if written_cards:
            console.print(f"[green]Wrote {len(written_cards)} remediation card(s) to {out_dir}[/]")
    if "md-single" in exports:
        single_path = render_remediation_cards_single(report.entries, out_dir / "remediation.md")
        console.print(f"[green]Wrote single remediation file to {single_path}[/]")
    if "json" in exports:
        json_path = export_report_json(report, out_dir / "triage-report.json")
        console.print(f"[green]Exported full report to {json_path}[/]")
    if "sarif" in exports:
        sarif_path = export_report_sarif(report, out_dir / "triage-report.sarif")
        console.print(f"[green]Exported SARIF to {sarif_path}[/]")

    if gate_threshold is not None:
        gate = evaluate_gate(report, gate_threshold, fail_on_error=fail_on_error)
        if not gate.passed:
            console.print(f"[red]Gate failed:[/] {gate['reason']}.")
            raise SystemExit(2)
        console.print(
            f"[green]Gate passed[/] (threshold {gate_threshold:g}, highest actionable risk {gate['max_risk']})."
        )
    elif report.errored_entries:
        err_console.print(
            f"[yellow]Warning:[/] {len(report.errored_entries)} finding(s) could not be triaged; "
            "re-run with --cache to retry only those."
        )


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
    _write_or_echo(rendered, output_path, "Wrote prioritized backlog to")
    if output_path and owner_source is not None:
        console.print(f"[dim]Annotated backlog with CODEOWNERS from {owner_source}[/]")


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
    _write_or_echo(rendered, output_path, "Wrote owner summary to")


@main.command(
    epilog="""
Examples:
  vulnsift autofix --input vulnsift-output/triage-report.json --list-only
  vulnsift autofix --input report.json --dry-run
  vulnsift autofix --input report.json --min-risk 8 --max-fixes 3 --min-confidence 8
  vulnsift autofix --input report.json --open-pr --draft

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
@click.option("--list-only", is_flag=True, help="Print eligible findings (no API calls, no disk writes).")
@click.option(
    "--min-risk", type=click.FloatRange(0, 10), default=7.0, show_default=True, help="Minimum risk score to fix."
)
@click.option(
    "--min-confidence",
    type=click.IntRange(0, 10),
    default=7,
    show_default=True,
    help="Only apply patches the model rates at least this confident.",
)
@click.option("--max-fixes", type=click.IntRange(min=1), default=None, help="Cap how many findings to send.")
@click.option("--repo-root", type=click.Path(exists=True, file_okay=False), default=".", help="Repository root.")
@click.option("--model", default=None, help="Claude model ID (default: from config or claude-opus-5-5).")
@click.option(
    "--open-pr",
    is_flag=True,
    help="Open one PR per fix from the current branch (requires a clean git tree and the gh CLI).",
)
@click.option("--draft", is_flag=True, help="With --open-pr, open the PRs as drafts.")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output (prints diffs of applied patches).")
def autofix(
    input_path: str,
    dry_run: bool,
    list_only: bool,
    min_risk: float,
    min_confidence: int,
    max_fixes: int | None,
    repo_root: str,
    model: str | None,
    open_pr: bool,
    draft: bool,
    verbose: bool,
) -> None:
    """Generate AI-powered code patches for high-risk findings (sends source code to the model)."""
    from rich.markup import escape

    from vulnsift.autofix import GitError, autofix_report, filter_eligible, open_fix_prs
    from vulnsift.llm import UsageTracker, make_client

    report_obj = _load_triage_report(input_path)
    cfg = _config()
    model = model or cfg.model
    root = Path(repo_root).resolve()

    eligible = filter_eligible(report_obj.entries, min_risk)
    if max_fixes is not None:
        eligible = eligible[:max_fixes]
    if not eligible:
        console.print("[yellow]No eligible findings for auto-fix at this min-risk.[/]")
        return

    if list_only:
        console.print(f"[dim]{len(eligible)} eligible finding(s) (no API calls):[/]")
        for e in eligible:
            console.print(
                f"  - [bold]{escape(e.finding.id)}[/] risk={e.triage.risk_score} "
                f"{escape(e.finding.location.file_path)}:{e.finding.location.start_line or '?'}"
            )
        return

    if open_pr and dry_run:
        _err_with_hint("--open-pr cannot be combined with --dry-run.")
    if open_pr:
        from vulnsift.autofix.github_pr import ensure_clean_worktree

        try:
            ensure_clean_worktree(root)
        except GitError as e:
            _err_with_hint(str(e), "Commit or stash your changes first; each fix gets its own branch and PR.")

    key = _require_api_key(cfg)
    console.print(f"[dim]Auto-fixing {len(eligible)} finding(s) with risk >= {min_risk:g} in {root} using {model}.[/]")
    console.print("[dim]Autofix sends finding metadata and full source files to the Anthropic API.[/]")

    tracker = UsageTracker(model)
    with progress_bar(console) as progress:
        task = progress.add_task("Generating patches", total=len(eligible), detail="")

        def on_progress(done: int, total: int, result) -> None:
            progress.update(task, completed=done)

        try:
            results = autofix_report(
                report_obj,
                root,
                client=make_client(key),
                model=model,
                # In PR mode patches are written on per-fix branches, never on the current checkout.
                dry_run=dry_run or open_pr,
                min_risk=min_risk,
                min_confidence=min_confidence,
                max_fixes=max_fixes,
                tracker=tracker,
                on_progress=on_progress,
            )
        except Exception as e:  # fatal API errors (auth, unknown model)
            from vulnsift.llm import describe_api_error

            _err_with_hint(f"Autofix aborted: {describe_api_error(e)}")

    ready = [r for r in results if r.skipped_reason is None]
    for r in results:
        color = "green" if r.confidence >= 7 else "yellow" if r.confidence >= 4 else "red"
        console.print(
            f"\n[bold]{escape(r.finding_id)}[/] ({escape(r.file_path)}) — confidence [{color}]{r.confidence}/10[/]"
        )
        if r.explanation:
            console.print(f"  {escape(r.explanation)}")
        if r.skipped_reason:
            console.print(f"  [yellow]Skipped:[/] {escape(r.skipped_reason)}")
        elif r.applied:
            console.print(f"  [green]Patch applied to {escape(r.file_path)}[/]")
        if r.diff and (dry_run or verbose) and r.skipped_reason is None:
            console.print(escape(r.diff), style="dim", highlight=False)

    render_usage(tracker.summary(), model=model, console=console)
    skipped = len(results) - len(ready)
    if dry_run:
        console.print(f"\n[dim]Dry run: {len(ready)} patch(es) ready, {skipped} skipped, none applied.[/]")
    elif not open_pr:
        console.print(f"\n[green]{sum(r.applied for r in results)} patch(es) applied[/], [yellow]{skipped} skipped[/]")

    if open_pr and ready:
        try:
            outcomes = open_fix_prs(root, ready, draft=draft)
        except GitError as e:
            _err_with_hint(str(e))
        for result, url, error in outcomes:
            if url:
                console.print(f"  [green]PR for {escape(result.finding_id)}:[/] {url}")
            else:
                console.print(f"  [red]Failed to open PR for {escape(result.finding_id)}:[/] {escape(error or '')}")


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
    "--fail-on-error/--allow-errors",
    default=True,
    help="Show the gate as failed when findings could not be triaged (default: yes).",
)
@click.option(
    "--output", "output_path", type=click.Path(), default=None, help="Write comment to file (default: stdout).",
)
def github_comment(input_path: str, threshold: float | None, fail_on_error: bool, output_path: str | None) -> None:
    """Render a GitHub PR comment from a triage report."""
    from vulnsift.output.github_comment import render_github_comment

    report_obj = _load_triage_report(input_path)
    md = render_github_comment(report_obj, threshold=threshold, fail_on_error=fail_on_error)
    _write_or_echo(md, output_path, "Wrote PR comment to")


@main.command(
    epilog="""
Examples:
  vulnsift store --input vulnsift-output/triage-report.json
  vulnsift store --input report.json --db-path ./my-dashboard.db
""",
)
@click.option("--input", "input_path", required=True, type=click.Path(exists=True), help="Triage report JSON file.")
@click.option("--db-path", type=click.Path(), default=None, help="Dashboard DB path (~/.vulnsift/dashboard.db).")
@click.option("--project", default=None, help="Project name (default: from the report, config, or 'default').")
def store(input_path: str, db_path: str | None, project: str | None) -> None:
    """Store a triage report in the dashboard database."""
    from vulnsift.dashboard.db import DEFAULT_DB_PATH, init_db, store_report

    report_obj = _load_triage_report(input_path)
    project = project or report_obj.project or _config().project

    conn = init_db(db_path or DEFAULT_DB_PATH)
    try:
        scan_id = store_report(conn, report_obj, project=project)
    finally:
        conn.close()
    console.print(f"[green]Stored report as scan #{scan_id}[/] (project: {project or 'default'})")


@main.command(
    epilog="""
Examples:
  vulnsift dashboard
  vulnsift dashboard --port 9090
  vulnsift dashboard --db-path ./my-dashboard.db
""",
)
@click.option("--port", type=click.IntRange(1, 65535), default=8080, show_default=True, help="Port to serve on.")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind to.")
@click.option("--db-path", type=click.Path(), default=None, help="Dashboard DB path (~/.vulnsift/dashboard.db).")
@click.option(
    "--token",
    envvar="VULNSIFT_DASHBOARD_TOKEN",
    default=None,
    help="Bearer token required for uploading/deleting scans via the API (env: VULNSIFT_DASHBOARD_TOKEN).",
)
def dashboard(port: int, host: str, db_path: str | None, token: str | None) -> None:
    """Launch the VulnSift web dashboard."""
    try:
        from vulnsift.dashboard.app import create_app, serve
    except ImportError:
        _err_with_hint(
            "Flask is required for the dashboard.",
            'Install with: pip install "vulnsift[dashboard]"',
        )

    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        err_console.print(
            "[yellow]Warning:[/] binding to a non-loopback address without --token; "
            "anyone who can reach it can upload or delete scans."
        )
    app = create_app(db_path=db_path, token=token)
    console.print(f"[green]VulnSift dashboard running at http://{host}:{port}[/]")
    serve(app, host=host, port=port)


if __name__ == "__main__":
    main()
