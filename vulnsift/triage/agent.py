"""Claude API triage: one structured request per finding -> TriageResult + RemediationCard."""

from __future__ import annotations

import anthropic

from vulnsift.llm import DEFAULT_MODEL, UsageTracker, make_client, structured_call
from vulnsift.models import RemediationCard, TriageResult, UnifiedFinding
from vulnsift.triage.prompts import SYSTEM_PROMPT, TriageOutput, build_user_prompt

# Triage answers are short; this leaves ample room for adaptive thinking on top.
TRIAGE_MAX_TOKENS = 16000


def _clamp(value: int, lo: int = 0, hi: int = 10) -> int:
    return max(lo, min(hi, int(value)))


def to_result(out: TriageOutput) -> tuple[TriageResult, RemediationCard]:
    """Map the model's structured output to VulnSift models (scores clamped to 0-10)."""
    triage = TriageResult(
        risk_score=_clamp(out.risk_score),
        is_likely_false_positive=out.is_likely_false_positive,
        confidence=_clamp(out.confidence),
        reasoning=out.reasoning.strip(),
        exploitability_notes=out.exploitability_notes.strip(),
    )
    card = RemediationCard(
        title=out.remediation_title.strip(),
        business_impact=out.business_impact.strip(),
        steps=[s.strip() for s in out.remediation_steps if s and s.strip()],
        code_snippet=out.code_snippet.strip() or None,
        reference_links=[u.strip() for u in out.reference_links if u.strip().startswith(("http://", "https://"))],
    )
    return triage, card


def triage_finding(
    finding: UnifiedFinding,
    project_context: str | None = None,
    *,
    client: anthropic.Anthropic | None = None,
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
    effort: str | None = None,
    redact_code: bool = False,
    tracker: UsageTracker | None = None,
) -> tuple[TriageResult, RemediationCard]:
    """Send one finding to Claude for triage. Returns (TriageResult, RemediationCard).

    Transient API errors are retried by the SDK; anything still failing is raised to the caller.
    When redact_code is True, code snippets from the finding are not included in the prompt.
    """
    client = client or make_client(api_key)
    out = structured_call(
        client,
        model=model,
        system=SYSTEM_PROMPT,
        user=build_user_prompt(finding, project_context, redact_code=redact_code),
        output_type=TriageOutput,
        max_tokens=TRIAGE_MAX_TOKENS,
        effort=effort,
        tracker=tracker,
    )
    return to_result(out)
