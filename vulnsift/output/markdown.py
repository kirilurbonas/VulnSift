"""Markdown remediation card generation."""

from __future__ import annotations

from pathlib import Path

from vulnsift.models import RemediationCard, TriageReportEntry


def render_remediation_card(entry: TriageReportEntry) -> str:
    """Render a single remediation card as Markdown."""
    card = entry.remediation
    if not card:
        return ""
    lines = [
        f"# {card.title}",
        "",
        "## Business impact",
        card.business_impact,
        "",
        "## Steps to fix",
    ]
    for i, step in enumerate(card.steps, 1):
        lines.append(f"{i}. {step}")
    if card.code_snippet:
        lines.extend(["", "## Code", "", "```", card.code_snippet.strip(), "```"])
    if card.reference_links:
        lines.extend(["", "## References"])
        for url in card.reference_links:
            lines.append(f"- {url}")
    return "\n".join(lines) + "\n"


def render_remediation_cards(
    entries: list[TriageReportEntry],
    output_dir: str | Path,
    *,
    only_actionable: bool = True,
) -> list[Path]:
    """
    Write one Markdown file per actionable finding (or all if only_actionable=False).
    Returns list of written paths.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if only_actionable:
        entries = [e for e in entries if not e.triage.is_likely_false_positive]
    written: list[Path] = []
    for i, entry in enumerate(entries):
        if not entry.remediation:
            continue
        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in entry.finding.id)[:50]
        path = output_dir / f"remediation_{i+1}_{safe_id}.md"
        path.write_text(render_remediation_card(entry), encoding="utf-8")
        written.append(path)
    return written
