"""System/user prompts and tool schema for Claude triage."""

from __future__ import annotations

from vulnsift.models import UnifiedFinding

SYSTEM_PROMPT = """You are an expert Application Security engineer performing vulnerability triage.
Your job is to assess each finding for real-world exploitability and likelihood of false positive.

Consider:
- Is the vulnerable code/data reachable from an attacker (e.g. user input, network)?
- Is authentication required? Is the component public-facing?
- Does the scanner often report false positives for this rule/pattern?
- Business context: language, environment (e.g. internal vs internet-facing), and any hints the user provided.

Output a VulnSift Risk Score 0-10: 0 = no real risk (e.g. false positive), 10 = directly exploitable, critical.
Be conservative: when in doubt, score higher and do not mark as false positive.
Always use the submit_triage tool to return your assessment and remediation."""

TOOL_SCHEMA = {
    "name": "submit_triage",
    "description": "Submit the triage result and remediation for this finding.",
    "input_schema": {
        "type": "object",
        "properties": {
            "risk_score": {
                "type": "integer",
                "description": "VulnSift Risk Score 0-10 (0=no risk/false positive, 10=critical exploitable)",
                "minimum": 0,
                "maximum": 10,
            },
            "is_likely_false_positive": {
                "type": "boolean",
                "description": "True if this finding is likely a false positive or not actionable.",
            },
            "reasoning": {
                "type": "string",
                "description": "Brief reasoning for the risk score and false positive flag.",
            },
            "exploitability_notes": {
                "type": "string",
                "description": "Notes on exploitability: reachability, auth required, etc.",
            },
            "remediation_title": {
                "type": "string",
                "description": "Short title for the remediation (e.g. 'Upgrade lodash to 4.17.21').",
            },
            "business_impact": {
                "type": "string",
                "description": "Plain-English business impact if exploited.",
            },
            "remediation_steps": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Step-by-step fix instructions for developers.",
            },
            "code_snippet": {
                "type": "string",
                "description": "Optional code snippet or patch hint for the fix.",
            },
            "reference_links": {
                "type": "array",
                "items": {"type": "string"},
                "description": "URLs to CVE, advisory, or fix documentation.",
            },
        },
        "required": [
            "risk_score",
            "is_likely_false_positive",
            "reasoning",
            "remediation_title",
            "business_impact",
            "remediation_steps",
        ],
    },
}


def build_user_prompt(
    finding: UnifiedFinding,
    project_context: str | None = None,
    *,
    redact_code: bool = False,
) -> str:
    """Build the user message for a single finding.

    When redact_code is True, do not include raw code snippets in the prompt.
    """
    parts = [
        "## Finding",
        f"**Rule/ID:** {finding.rule_id}",
        f"**Title:** {finding.title}",
        f"**Severity (scanner):** {finding.severity}",
        f"**Message:** {finding.message}",
        "",
        f"**Description:** {finding.description or '(none)'}",
    ]
    if finding.cve:
        parts.append(f"**CVE:** {finding.cve}")
    if finding.cwe:
        parts.append(f"**CWE:** {finding.cwe}")
    if finding.location and finding.location.file_path:
        parts.append(f"**File:** {finding.location.file_path}")
        if finding.location.start_line is not None:
            parts.append(f"**Line:** {finding.location.start_line}")
        if finding.location.snippet:
            if redact_code:
                parts.append("**Snippet:** (redacted; code not sent to model)")
            else:
                parts.append(f"**Snippet:**\n```\n{finding.location.snippet}\n```")
    if project_context:
        parts.append("")
        parts.append("## Project context (for risk assessment)")
        parts.append(project_context)
    parts.append("")
    parts.append("Assess this finding and call submit_triage with your assessment and remediation.")
    return "\n".join(parts)
