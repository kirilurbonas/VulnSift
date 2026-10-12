"""Escaping helpers shared by the Markdown/CSV renderers."""

from __future__ import annotations

import html

_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: object) -> object:
    """Neutralise spreadsheet formula injection in a CSV cell (scanner/AI text is untrusted)."""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def md_cell(value: object, limit: int | None = None) -> str:
    """Escape text for a Markdown table cell (pipes, newlines, HTML)."""
    text = " ".join(str(value if value is not None else "").split())
    if limit is not None and len(text) > limit:
        text = text[: limit - 1] + "…"
    return html.escape(text, quote=False).replace("|", "\\|")


def md_code(value: object) -> str:
    """Inline code span for a table cell that survives backticks and pipes inside the value."""
    text = " ".join(str(value or "-").split()).replace("|", "\\|")
    if "`" in text:
        return f"`` {text} ``"
    return f"`{text}`"
