"""Tests for patch application, validation, and diff utilities."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnsift.autofix.patches import (
    PatchError,
    UnsafePathError,
    apply_edits,
    apply_patch,
    generate_diff,
    read_source,
    resolve_repo_path,
    validate_patch,
)
from vulnsift.autofix.prompts import PatchEdit


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


class TestApplyPatchAtomic:
    def test_preserves_crlf(self, tmp_path: Path):
        f = tmp_path / "example.py"
        f.write_bytes(b"x = 1\r\ny = 2\r\n")
        assert apply_patch(f, "x = 1\r\ny = 2\r\n", "x = 1\ny = 3\n") is True
        assert f.read_bytes() == b"x = 1\r\ny = 3\r\n"

    def test_no_temp_files_left(self, tmp_path: Path):
        f = tmp_path / "example.py"
        f.write_text("a = 1\n", encoding="utf-8")
        apply_patch(f, "a = 1\n", "a = 2\n")
        assert [p.name for p in tmp_path.iterdir()] == ["example.py"]


class TestApplyEdits:
    def test_sequential(self):
        out = apply_edits("a\nb\nc\n", [PatchEdit(old="a\n", new="A\n"), PatchEdit(old="A\nb", new="AB")])
        assert out == "AB\nc\n"

    def test_ambiguous(self):
        with pytest.raises(PatchError, match="ambiguous"):
            apply_edits("x\nx\n", [PatchEdit(old="x", new="y")])

    def test_not_found(self):
        with pytest.raises(PatchError, match="not found"):
            apply_edits("x\n", [PatchEdit(old="z", new="y")])

    def test_empty_old(self):
        with pytest.raises(PatchError, match="empty"):
            apply_edits("x\n", [PatchEdit(old="", new="y")])

    def test_crlf_in_edit_normalised(self):
        assert apply_edits("a\nb\n", [PatchEdit(old="a\r\nb", new="c\r\nd")]) == "c\nd\n"


class TestStructuredValidation:
    def test_json(self, tmp_path: Path):
        assert validate_patch(tmp_path / "p.json", '{"a": 1}') == []
        assert any("JSON" in e for e in validate_patch(tmp_path / "p.json", '{"a": 1,}'))

    def test_yaml(self, tmp_path: Path):
        assert validate_patch(tmp_path / "c.yml", "a: 1\n---\nb: 2\n") == []
        assert any("YAML" in e for e in validate_patch(tmp_path / "c.yaml", "a: [1\n"))

    def test_toml(self, tmp_path: Path):
        assert validate_patch(tmp_path / "pyproject.toml", '[x]\ny = "1"\n') == []
        assert any("TOML" in e for e in validate_patch(tmp_path / "pyproject.toml", "[x\n"))

    def test_skips_check_when_original_already_invalid(self, tmp_path: Path):
        templated = "a: {{ .Values.x }\n"
        assert validate_patch(tmp_path / "t.yaml", templated + "b: 1\n", templated) == []


class TestResolveRepoPath:
    def test_inside(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("x", encoding="utf-8")
        assert resolve_repo_path(tmp_path, "a.py") == (tmp_path / "a.py").resolve()
        assert resolve_repo_path(tmp_path, "./sub/../a.py") == (tmp_path / "a.py").resolve()

    @pytest.mark.parametrize("bad", ["../x.py", "/etc/passwd", "", "a\0b"])
    def test_rejected(self, tmp_path: Path, bad: str):
        with pytest.raises(UnsafePathError):
            resolve_repo_path(tmp_path / "repo", bad)


class TestReadSource:
    def test_crlf_normalised(self, tmp_path: Path):
        f = tmp_path / "a.py"
        f.write_bytes(b"a\r\nb\r\n")
        src = read_source(f)
        assert src.content == "a\nb\n" and src.newline == "\r\n"

    def test_mixed_left_alone(self, tmp_path: Path):
        f = tmp_path / "a.py"
        f.write_bytes(b"a\r\nb\n")
        src = read_source(f)
        assert src.content == "a\r\nb\n" and src.newline == "\n"

    def test_non_utf8(self, tmp_path: Path):
        f = tmp_path / "a.py"
        f.write_bytes(b"\xff\xfe x")
        with pytest.raises(PatchError, match="UTF-8"):
            read_source(f)
