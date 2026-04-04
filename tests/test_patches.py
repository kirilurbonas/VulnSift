"""Tests for patch application, validation, and diff utilities."""

from __future__ import annotations

from pathlib import Path

from vulnsift.autofix.patches import apply_patch, generate_diff, validate_patch


class TestApplyPatch:
    def test_applies_patch(self, tmp_path: Path):
        f = tmp_path / "example.py"
        original = "x = 1\ny = 2\n"
        f.write_text(original, encoding="utf-8")
        patched = "x = 1\ny = 3\n"
        assert apply_patch(f, original, patched) is True
        assert f.read_text(encoding="utf-8") == patched

    def test_no_change(self, tmp_path: Path):
        f = tmp_path / "example.py"
        content = "x = 1\n"
        f.write_text(content, encoding="utf-8")
        assert apply_patch(f, content, content) is False


class TestValidatePatch:
    def test_valid_python(self, tmp_path: Path):
        f = tmp_path / "example.py"
        errors = validate_patch(f, "x = 1\nprint(x)\n")
        assert errors == []

    def test_invalid_python(self, tmp_path: Path):
        f = tmp_path / "example.py"
        errors = validate_patch(f, "def foo(\n")
        assert len(errors) == 1
        assert "syntax error" in errors[0].lower()

    def test_empty_content(self, tmp_path: Path):
        f = tmp_path / "example.py"
        errors = validate_patch(f, "   ")
        assert any("empty" in e.lower() for e in errors)

    def test_unbalanced_braces_js(self, tmp_path: Path):
        f = tmp_path / "example.js"
        errors = validate_patch(f, "function foo() {\n  return 1;\n")
        assert any("brace" in e.lower() for e in errors)

    def test_balanced_braces_js(self, tmp_path: Path):
        f = tmp_path / "example.js"
        errors = validate_patch(f, "function foo() {\n  return 1;\n}\n")
        assert errors == []

    def test_unknown_extension(self, tmp_path: Path):
        f = tmp_path / "data.txt"
        errors = validate_patch(f, "hello world")
        assert errors == []


class TestGenerateDiff:
    def test_generates_diff(self):
        original = "line1\nline2\nline3\n"
        patched = "line1\nline2_modified\nline3\n"
        diff = generate_diff(Path("test.py"), original, patched)
        assert "---" in diff
        assert "+++" in diff
        assert "-line2" in diff
        assert "+line2_modified" in diff

    def test_no_diff_when_identical(self):
        content = "same\n"
        diff = generate_diff(Path("test.py"), content, content)
        assert diff == ""
