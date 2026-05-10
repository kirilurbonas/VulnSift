"""Auto-fix agent: generate patches for triaged vulnerabilities using Claude."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from anthropic import Anthropic
from anthropic.types import MessageParam, ToolParam

from vulnsift.autofix.patches import validate_patch
from vulnsift.autofix.prompts import (
    AUTOFIX_SYSTEM_PROMPT,
    SUBMIT_PATCH_TOOL,
    build_autofix_prompt,
)
from vulnsift.models import (
    AutofixResult,
    RemediationCard,
    TriageReport,
    TriageReportEntry,
    TriageResult,
    UnifiedFinding,
)

DEFAULT_MODEL = "claude-sonnet-4-20250514"
MAX_RETRIES = 2

# Maximum source file size to send to the model (chars).
MAX_SOURCE_SIZE = 100_000


def autofix_finding(
    finding: UnifiedFinding,
    triage: TriageResult,
    remediation: RemediationCard,
    source_code: str,
    *,
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
) -> AutofixResult:
    """Generate a patch for a single finding.

    Calls Claude with the finding context, remediation guidance, and full source
    file to produce a patched version of the code.
    """
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY not set. Set the env var or pass api_key=.")

    user_content = build_autofix_prompt(
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity,
        description=finding.description,
        cwe=finding.cwe,
        file_path=finding.location.file_path,
        start_line=finding.location.start_line,
        snippet=finding.location.snippet,
        source_code=source_code,
        remediation_steps=remediation.steps,
        remediation_code_hint=remediation.code_snippet,
    )

    tools: list[ToolParam] = [
        {
            "name": SUBMIT_PATCH_TOOL["name"],
            "description": SUBMIT_PATCH_TOOL["description"],
            "input_schema": SUBMIT_PATCH_TOOL["input_schema"],
        }
    ]
    messages: list[MessageParam] = [{"role": "user", "content": user_content}]

    client = Anthropic(api_key=key)
    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            response = client.messages.create(
                model=model,
                max_tokens=4096,
                system=AUTOFIX_SYSTEM_PROMPT,
                messages=messages,
                tools=tools,
                tool_choice={"type": "tool", "name": "submit_patch"},
            )
            return _parse_patch_response(response, finding, source_code)
        except Exception as e:
            last_error = e
            if attempt == MAX_RETRIES:
                raise
            continue

    if last_error:
        raise last_error
    raise RuntimeError("Autofix failed after retries")


def _parse_patch_response(
    response: Any,
    finding: UnifiedFinding,
    source_code: str,
) -> AutofixResult:
    """Extract submit_patch tool use from response and build AutofixResult."""
    content = getattr(response, "content", []) or []
    for block in content:
        if getattr(block, "type", None) != "tool_use":
            continue
        if getattr(block, "name", None) != "submit_patch":
            continue
        inp = getattr(block, "input", None) or {}
        if not isinstance(inp, dict):
            continue
        return AutofixResult(
            finding_id=finding.id,
            file_path=finding.location.file_path,
            original_snippet=source_code,
            patched_snippet=str(inp.get("patched_code", "")),
            explanation=str(inp.get("explanation", "")),
            confidence=int(inp.get("confidence", 0)),
        )
    raise ValueError("Claude response did not include submit_patch tool use")


def autofix_report(
    report: TriageReport,
    repo_root: Path,
    *,
    dry_run: bool = False,
    min_risk: float = 7.0,
    max_fixes: int | None = None,
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
) -> list[AutofixResult]:
    """Generate patches for all eligible findings in a triage report.

    Eligible = risk_score >= min_risk, not false positive, has a file path.
    Returns a list of AutofixResult objects (one per eligible finding).
    """
    eligible = _filter_eligible(report.entries, min_risk)
    if max_fixes is not None and max_fixes > 0:
        eligible = eligible[:max_fixes]
    results: list[AutofixResult] = []

    for entry in eligible:
        file_path = repo_root / entry.finding.location.file_path
        if not file_path.is_file():
            continue

        source_code = file_path.read_text(encoding="utf-8", errors="replace")
        if len(source_code) > MAX_SOURCE_SIZE:
            continue

        result = autofix_finding(
            entry.finding,
            entry.triage,
            entry.remediation,  # type: ignore[arg-type]
            source_code,
            api_key=api_key,
            model=model,
        )

        # Validate the patch
        errors = validate_patch(file_path, result.patched_snippet)
        if errors:
            result.confidence = 0
            result.explanation += f" [Validation errors: {'; '.join(errors)}]"

        if not dry_run and result.confidence > 0:
            from vulnsift.autofix.patches import apply_patch

            result.applied = apply_patch(file_path, source_code, result.patched_snippet)

        results.append(result)

    return results


def _filter_eligible(entries: list[TriageReportEntry], min_risk: float) -> list[TriageReportEntry]:
    """Return entries eligible for auto-fix."""
    return [
        e
        for e in entries
        if e.triage.risk_score >= min_risk
        and not e.triage.is_likely_false_positive
        and e.finding.location.file_path
        and e.remediation is not None
    ]
