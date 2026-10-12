"""Auto-fix agent: generate and apply minimal patches for triaged vulnerabilities using Claude."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import anthropic

from vulnsift.autofix.patches import (
    MAX_SOURCE_SIZE,
    PatchError,
    apply_edits,
    generate_diff,
    read_source,
    resolve_repo_path,
    validate_patch,
    write_atomic,
)
from vulnsift.autofix.prompts import AUTOFIX_SYSTEM_PROMPT, PatchProposal, build_autofix_prompt
from vulnsift.llm import DEFAULT_MODEL, LLMError, UsageTracker, describe_api_error, is_fatal_api_error, make_client
from vulnsift.llm import structured_call as structured_call  # re-exported so tests can patch it here
from vulnsift.models import (
    AutofixResult,
    RemediationCard,
    TriageReport,
    TriageReportEntry,
    TriageResult,
    UnifiedFinding,
)

__all__ = [
    "AUTOFIX_MAX_TOKENS",
    "DEFAULT_MIN_CONFIDENCE",
    "MAX_SOURCE_SIZE",
    "ProgressCallback",
    "autofix_finding",
    "autofix_report",
    "filter_eligible",
]

AUTOFIX_MAX_TOKENS = 16000
DEFAULT_MIN_CONFIDENCE = 7

# on_progress(done, total, result): called after each eligible finding has been processed.
ProgressCallback = Callable[[int, int, AutofixResult], None]


def _clamp(value: int) -> int:
    return max(0, min(10, int(value)))


def autofix_finding(
    finding: UnifiedFinding,
    triage: TriageResult,
    remediation: RemediationCard,
    source_code: str,
    *,
    client: anthropic.Anthropic | None = None,
    model: str = DEFAULT_MODEL,
    tracker: UsageTracker | None = None,
    file_path: str | None = None,
) -> AutofixResult:
    """Ask Claude for a patch for one finding and apply it in memory (never touches disk).

    `source_code` should use '\\n' line endings. The returned result has `original_snippet` (the
    source), `patched_snippet` (full new content) and `diff` filled in when the edits apply and
    validate; otherwise `skipped_reason` explains why. API/LLM errors are raised to the caller.
    """
    path = file_path or finding.location.file_path
    client = client or make_client()
    user = build_autofix_prompt(
        rule_id=finding.rule_id,
        title=finding.title or finding.message,
        severity=finding.severity,
        description=finding.description,
        cwe=finding.cwe,
        file_path=path,
        start_line=finding.location.start_line,
        snippet=finding.location.snippet,
        source_code=source_code,
        remediation_steps=remediation.steps,
        remediation_code_hint=remediation.code_snippet,
        risk_score=triage.risk_score,
        triage_reasoning=triage.reasoning or None,
    )
    proposal = structured_call(
        client,
        model=model,
        system=AUTOFIX_SYSTEM_PROMPT,
        user=user,
        output_type=PatchProposal,
        max_tokens=AUTOFIX_MAX_TOKENS,
        tracker=tracker,
    )
    result = AutofixResult(
        finding_id=finding.id,
        file_path=path,
        original_snippet=source_code,
        explanation=proposal.explanation.strip(),
        confidence=_clamp(proposal.confidence),
    )
    if not proposal.edits:
        result.skipped_reason = "model did not propose a fix"
        return result
    try:
        patched = apply_edits(source_code, proposal.edits)
    except PatchError as e:
        result.skipped_reason = f"patch rejected: {e}"
        return result
    if patched == source_code:
        result.skipped_reason = "patch makes no changes"
        return result
    result.patched_snippet = patched
    result.diff = generate_diff(path, source_code, patched)
    errors = validate_patch(Path(path), patched, source_code)
    if errors:
        result.skipped_reason = f"patch failed validation: {'; '.join(errors)}"
    return result


def filter_eligible(entries: list[TriageReportEntry], min_risk: float) -> list[TriageReportEntry]:
    """Entries eligible for auto-fix: actionable (assessed, not FP), risk >= min_risk, with a file and remediation."""
    return [
        e
        for e in entries
        if e.is_actionable
        and e.triage.risk_score >= min_risk
        and e.finding.location.file_path
        and e.remediation is not None
    ]


_filter_eligible = filter_eligible  # backwards-compatible alias


def _process_entry(
    entry: TriageReportEntry,
    root: Path,
    *,
    client: anthropic.Anthropic,
    model: str,
    dry_run: bool,
    min_confidence: int,
    tracker: UsageTracker | None,
) -> AutofixResult:
    finding = entry.finding
    result = AutofixResult(finding_id=finding.id, file_path=finding.location.file_path)
    try:
        target = resolve_repo_path(root, finding.location.file_path)
        rel = target.relative_to(root).as_posix()
        result.file_path = rel
        source = read_source(target)
        assert entry.remediation is not None  # guaranteed by filter_eligible
        result = autofix_finding(
            finding,
            entry.triage,
            entry.remediation,
            source.content,
            client=client,
            model=model,
            tracker=tracker,
            file_path=rel,
        )
        if result.skipped_reason is None and result.confidence < min_confidence:
            result.skipped_reason = f"confidence {result.confidence}/10 is below min_confidence {min_confidence}"
        if result.skipped_reason is None and not dry_run:
            write_atomic(target, result.patched_snippet, newline=source.newline)
            result.applied = True
    except PatchError as e:
        result.skipped_reason = str(e)
    except LLMError as e:
        result.skipped_reason = f"model error: {e}"
    except OSError as e:
        result.skipped_reason = f"file error: {e}"
    except Exception as e:
        if is_fatal_api_error(e):
            raise
        result.skipped_reason = f"API call failed: {describe_api_error(e)}"
    return result


def autofix_report(
    report: TriageReport,
    repo_root: Path | str,
    *,
    client: anthropic.Anthropic | None = None,
    model: str = DEFAULT_MODEL,
    dry_run: bool = False,
    min_risk: float = 7.0,
    min_confidence: int = DEFAULT_MIN_CONFIDENCE,
    max_fixes: int | None = None,
    tracker: UsageTracker | None = None,
    on_progress: ProgressCallback | None = None,
) -> list[AutofixResult]:
    """Generate (and unless dry_run, apply) patches for every eligible finding in a triage report.

    Returns one AutofixResult per eligible finding (capped at max_fixes, in report order). A result is
    either applied (`applied=True`), ready but not written (dry_run, `skipped_reason is None`), or skipped
    with `skipped_reason` set (unsafe path, binary/oversized file, ambiguous edit, failed validation,
    confidence below min_confidence, per-finding API error, ...). Only fatal API errors (auth, permission,
    unknown model) are raised. Nothing is written to disk when dry_run is True.
    """
    root = Path(repo_root).resolve()
    eligible = filter_eligible(report.entries, min_risk)
    if max_fixes is not None and max_fixes > 0:
        eligible = eligible[:max_fixes]
    if not eligible:
        return []
    client = client or make_client()

    results: list[AutofixResult] = []
    for i, entry in enumerate(eligible, 1):
        result = _process_entry(
            entry,
            root,
            client=client,
            model=model,
            dry_run=dry_run,
            min_confidence=min_confidence,
            tracker=tracker,
        )
        results.append(result)
        if on_progress is not None:
            on_progress(i, len(eligible), result)
    return results
