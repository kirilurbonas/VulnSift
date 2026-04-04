"""System prompt and tool schema for the auto-fix agent."""

from __future__ import annotations

AUTOFIX_SYSTEM_PROMPT = """\
You are an expert security engineer writing minimal, safe code patches to fix vulnerabilities.

Guidelines:
- Produce the SMALLEST change that fully resolves the vulnerability.
- Do NOT refactor surrounding code, add features, or change unrelated logic.
- Preserve the existing code style (indentation, naming, imports).
- If the fix requires a new import, add it at the top of the file.
- For dependency upgrades (e.g. npm/pip), output the updated dependency line only.
- Set confidence to 0-10: 10 = certain the patch is correct and complete, 0 = speculative.
- If you cannot produce a safe fix, set confidence to 0 and explain why.

Always use the submit_patch tool to return your patch."""

SUBMIT_PATCH_TOOL = {
    "name": "submit_patch",
    "description": "Submit a code patch that fixes the identified vulnerability.",
    "input_schema": {
        "type": "object",
        "properties": {
            "patched_code": {
                "type": "string",
                "description": (
                    "The patched version of the affected code. For source files, provide the full "
                    "file content with the fix applied. For dependency files, provide only the "
                    "changed lines."
                ),
            },
            "explanation": {
                "type": "string",
                "description": "Brief explanation of what the patch changes and why it fixes the vulnerability.",
            },
            "confidence": {
                "type": "integer",
                "description": "Confidence that this patch is correct and complete (0-10).",
                "minimum": 0,
                "maximum": 10,
            },
        },
        "required": ["patched_code", "explanation", "confidence"],
    },
}


def build_autofix_prompt(
    *,
    rule_id: str,
    title: str,
    severity: str,
    description: str,
    cwe: str | None,
    file_path: str,
    start_line: int | None,
    snippet: str | None,
    source_code: str,
    remediation_steps: list[str],
    remediation_code_hint: str | None,
) -> str:
    """Build the user prompt for the auto-fix agent."""
    parts = [
        "## Vulnerability to fix",
        f"**Rule:** {rule_id}",
        f"**Title:** {title}",
        f"**Severity:** {severity}",
        f"**Description:** {description}",
    ]
    if cwe:
        parts.append(f"**CWE:** {cwe}")
    parts.append(f"**File:** {file_path}")
    if start_line is not None:
        parts.append(f"**Line:** {start_line}")
    if snippet:
        parts.extend(["", "### Vulnerable snippet", f"```\n{snippet}\n```"])

    parts.extend(["", "## Remediation guidance"])
    for i, step in enumerate(remediation_steps, 1):
        parts.append(f"{i}. {step}")
    if remediation_code_hint:
        parts.extend(["", "### Suggested fix pattern", f"```\n{remediation_code_hint}\n```"])

    parts.extend([
        "",
        "## Full source file",
        f"```\n{source_code}\n```",
        "",
        "Generate the patched file using the submit_patch tool.",
    ])
    return "\n".join(parts)
