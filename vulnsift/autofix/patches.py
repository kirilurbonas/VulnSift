"""Patch utilities: safe path resolution, search/replace edits, validation, diffs, atomic writes."""

from __future__ import annotations

import ast
import difflib
import json
import os
import stat
import tempfile
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

# Largest source file (bytes) we will send to the model or patch.
MAX_SOURCE_SIZE = 100_000

_BRACE_SUFFIXES = (
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".java", ".go", ".c", ".h", ".cpp", ".cc", ".rs", ".cs",
)


class PatchError(ValueError):
    """A patch could not be applied safely (bad path, unreadable file, ambiguous edit, ...)."""


class UnsafePathError(PatchError):
    """The finding's file path points outside the repository or at something that is not a regular file."""


class EditLike(Protocol):
    old: str
    new: str


@dataclass(frozen=True)
class SourceFile:
    """A text file read for patching. `content` uses '\\n' line endings if the file was pure CRLF."""

    path: Path
    content: str
    newline: str  # "\n" or "\r\n": the style to restore when writing


def resolve_repo_path(repo_root: Path | str, file_path: str) -> Path:
    """Resolve `file_path` (relative to `repo_root`, or absolute) to a regular file inside the repo.

    Symlinks are resolved first, so a link pointing outside the repository is rejected.
    Raises UnsafePathError otherwise.
    """
    if not file_path or not file_path.strip():
        raise UnsafePathError("finding has no file path")
    if "\0" in file_path:
        raise UnsafePathError("file path contains a NUL byte")
    root = Path(repo_root).resolve()
    try:
        target = (root / file_path).resolve()
    except (OSError, RuntimeError) as e:  # RuntimeError: symlink loop on older Pythons
        raise UnsafePathError(f"cannot resolve path {file_path!r}: {e}") from e
    if not target.is_relative_to(root):
        raise UnsafePathError(f"path {file_path!r} resolves outside the repository root")
    if not target.exists():
        raise UnsafePathError(f"file not found: {file_path}")
    if not target.is_file():
        raise UnsafePathError(f"not a regular file: {file_path}")
    return target


def detect_newline(text: str) -> str:
    """'\\r\\n' when every line ending is CRLF, else '\\n' (mixed files are left untouched)."""
    crlf = text.count("\r\n")
    if crlf and crlf == text.count("\n"):
        return "\r\n"
    return "\n"


def read_source(path: Path, *, max_size: int = MAX_SOURCE_SIZE) -> SourceFile:
    """Read a UTF-8 text file for patching. Raises PatchError for binary, oversized, or non-UTF-8 files."""
    size = path.stat().st_size
    if size > max_size:
        raise PatchError(f"file is too large to auto-fix ({size} bytes > {max_size})")
    data = path.read_bytes()
    if b"\0" in data[:8192]:
        raise PatchError("file appears to be binary")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise PatchError("file is not valid UTF-8 text") from e
    newline = detect_newline(text)
    if newline == "\r\n":
        text = text.replace("\r\n", "\n")
    return SourceFile(path=path, content=text, newline=newline)


def apply_edits(content: str, edits: Iterable[EditLike]) -> str:
    """Apply search/replace edits in order, in memory.

    Each edit's `old` must be non-empty and occur exactly once in the content as it stands when the
    edit is applied; otherwise PatchError is raised and nothing is applied.
    """
    result = content
    for i, edit in enumerate(edits, 1):
        old = edit.old.replace("\r\n", "\n")
        new = edit.new.replace("\r\n", "\n")
        if not old:
            raise PatchError(f"edit {i}: empty 'old' text")
        count = result.count(old)
        if count == 0:
            raise PatchError(f"edit {i}: 'old' text not found in file")
        if count > 1:
            raise PatchError(f"edit {i}: 'old' text is ambiguous ({count} matches); needs more context")
        result = result.replace(old, new, 1)
    return result


def _syntax_errors(suffix: str, content: str, file_path: Path) -> list[str]:
    if suffix == ".py":
        try:
            ast.parse(content, filename=str(file_path))
        except SyntaxError as e:
            return [f"Python syntax error: {e}"]
    elif suffix in _BRACE_SUFFIXES:
        opens, closes = content.count("{"), content.count("}")
        if opens != closes:
            return [f"Unbalanced braces: {opens} opening vs {closes} closing"]
    elif suffix == ".json":
        try:
            json.loads(content)
        except ValueError as e:
            return [f"Invalid JSON: {e}"]
    elif suffix in (".yml", ".yaml"):
        try:
            import yaml
        except ImportError:  # pragma: no cover - pyyaml is a dependency
            return []
        try:
            for _ in yaml.safe_load_all(content):
                pass
        except yaml.YAMLError as e:
            return [f"Invalid YAML: {e}"]
    elif suffix == ".toml":
        try:
            tomllib.loads(content)
        except tomllib.TOMLDecodeError as e:
            return [f"Invalid TOML: {e}"]
    return []


def validate_patch(file_path: Path, patched_content: str, original_content: str | None = None) -> list[str]:
    """Return a list of validation errors (empty means valid).

    Python files are parsed with ast; brace languages get a brace-balance check; .json, .yml/.yaml and
    .toml files must parse. When `original_content` is given and already fails the syntax check (e.g. a
    templated YAML file), the syntax check is skipped: the patch can't be judged by it.
    """
    errors: list[str] = []
    if not patched_content.strip():
        errors.append("Patched content is empty")
    suffix = file_path.suffix.lower()
    syntax = _syntax_errors(suffix, patched_content, file_path)
    if syntax and original_content is not None and _syntax_errors(suffix, original_content, file_path):
        syntax = []
    errors.extend(syntax)
    return errors


def generate_diff(file_path: Path | str, original_content: str, patched_content: str) -> str:
    """Return a unified diff string (empty when identical)."""
    name = Path(file_path).as_posix()
    diff = difflib.unified_diff(
        original_content.splitlines(keepends=True),
        patched_content.splitlines(keepends=True),
        fromfile=f"a/{name}",
        tofile=f"b/{name}",
    )
    out = []
    for line in diff:
        out.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return "".join(out)


def write_atomic(path: Path, content: str, *, newline: str = "\n") -> None:
    """Write `content` (LF line endings) to `path` atomically, converting to `newline` and keeping file mode."""
    data = content.replace("\r\n", "\n")
    if newline != "\n":
        data = data.replace("\n", newline)
    try:
        mode: int | None = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        mode = None
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".vulnsift-tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data.encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def apply_patch(file_path: Path, original_content: str, patched_content: str, *, newline: str | None = None) -> bool:
    """Atomically replace the file content with the patched version.

    `newline` defaults to the style detected from `original_content`. Returns False (and writes
    nothing) when the contents are identical.
    """
    if original_content.replace("\r\n", "\n") == patched_content.replace("\r\n", "\n"):
        return False
    write_atomic(file_path, patched_content, newline=newline or detect_newline(original_content))
    return True
