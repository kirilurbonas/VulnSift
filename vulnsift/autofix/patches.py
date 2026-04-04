"""Patch application, validation, and diff utilities."""

from __future__ import annotations

import ast
import difflib
from pathlib import Path


def apply_patch(file_path: Path, original_content: str, patched_content: str) -> bool:
    """Replace the file content with the patched version.

    Returns True if the file was modified, False if contents are identical.
    """
    if original_content == patched_content:
        return False
    file_path.write_text(patched_content, encoding="utf-8")
    return True


def validate_patch(file_path: Path, patched_content: str) -> list[str]:
    """Return a list of validation errors (empty means valid).

    For Python files, runs ast.parse. For others, performs basic checks.
    """
    errors: list[str] = []
    suffix = file_path.suffix.lower()

    if suffix == ".py":
        try:
            ast.parse(patched_content, filename=str(file_path))
        except SyntaxError as e:
            errors.append(f"Python syntax error: {e}")
    elif suffix in (".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".c", ".cpp", ".rs"):
        # Basic brace balance check
        opens = patched_content.count("{")
        closes = patched_content.count("}")
        if opens != closes:
            errors.append(f"Unbalanced braces: {opens} opening vs {closes} closing")

    if not patched_content.strip():
        errors.append("Patched content is empty")

    return errors


def generate_diff(file_path: Path, original_content: str, patched_content: str) -> str:
    """Return a unified diff string."""
    original_lines = original_content.splitlines(keepends=True)
    patched_lines = patched_content.splitlines(keepends=True)
    diff = difflib.unified_diff(
        original_lines,
        patched_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
    )
    return "".join(diff)
