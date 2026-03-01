"""Claude API triage: call API, parse tool-use response into TriageResult + RemediationCard."""

from __future__ import annotations

import os
from typing import Any

from anthropic import Anthropic
from anthropic.types import MessageParam, ToolParam

from vulnsift.models import (
    RemediationCard,
    TriageResult,
    UnifiedFinding,
)
from vulnsift.triage.prompts import (
    SYSTEM_PROMPT,
    TOOL_SCHEMA,
    build_user_prompt,
)

DEFAULT_MODEL = "claude-sonnet-4-20250514"
MAX_RETRIES = 2


def triage_finding(
    finding: UnifiedFinding,
    project_context: str | None = None,
    *,
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
) -> tuple[TriageResult, RemediationCard]:
    """
    Send one finding to Claude for triage. Returns (TriageResult, RemediationCard).
    Raises on API or parsing errors after retries.
    """
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY not set. Set the env var or pass api_key=."
        )

    tools: list[ToolParam] = [
        {
            "name": TOOL_SCHEMA["name"],
            "description": TOOL_SCHEMA["description"],
            "input_schema": TOOL_SCHEMA["input_schema"],
        }
    ]

    user_content = build_user_prompt(finding, project_context)
    messages: list[MessageParam] = [{"role": "user", "content": user_content}]

    client = Anthropic(api_key=key)
    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            response = client.messages.create(
                model=model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=messages,
                tools=tools,
                tool_choice={"type": "tool", "name": "submit_triage"},
            )
            return _parse_tool_use(response)
        except Exception as e:
            last_error = e
            if attempt == MAX_RETRIES:
                raise
            continue

    if last_error:
        raise last_error
    raise RuntimeError("Triage failed after retries")


def _parse_tool_use(response: Any) -> tuple[TriageResult, RemediationCard]:
    """Extract submit_triage tool use from response and map to TriageResult + RemediationCard."""
    content = getattr(response, "content", []) or []
    for block in content:
        if getattr(block, "type", None) != "tool_use":
            continue
        if getattr(block, "name", None) != "submit_triage":
            continue
        inp = getattr(block, "input", None) or {}
        if not isinstance(inp, dict):
            continue
        triage = TriageResult(
            risk_score=int(inp.get("risk_score", 5)),
            is_likely_false_positive=bool(inp.get("is_likely_false_positive", False)),
            reasoning=str(inp.get("reasoning", "")),
            exploitability_notes=str(inp.get("exploitability_notes", "")),
        )
        card = RemediationCard(
            title=str(inp.get("remediation_title", "")),
            business_impact=str(inp.get("business_impact", "")),
            steps=[str(s) for s in (inp.get("remediation_steps") or [])],
            code_snippet=str(inp["code_snippet"]) if inp.get("code_snippet") else None,
            reference_links=[str(u) for u in (inp.get("reference_links") or [])],
        )
        return triage, card

    raise ValueError("Claude response did not include submit_triage tool use")