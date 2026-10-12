"""Shared helpers for scanner parsers (JSON loading, CWE/CVE extraction, severity mapping)."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
# Matches "CWE-79", "cwe-079", "CWE 89", "external/cwe/cwe-079", "CWE-89: SQL Injection".
CWE_RE = re.compile(r"\bcwe[-_ /:]*0*(\d+)", re.IGNORECASE)


def load_json(path: str | Path, label: str) -> Any:
    """Read and decode a JSON scan file. Raises FileNotFoundError / ValueError naming the file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"{label} file not found: {path}")
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    if not raw.strip():
        raise ValueError(f"Invalid JSON in {label} file {path}: file is empty")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {label} file {path}: {e}") from e


def normalize_cwe(value: Any) -> str | None:
    """Normalize a CWE reference ("external/cwe/cwe-079", "CWE-89: SQLi", 79) to "CWE-79"."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"CWE-{value}"
    m = CWE_RE.search(str(value))
    return f"CWE-{int(m.group(1))}" if m else None


def extract_cwes(values: Iterable[Any]) -> list[str]:
    """Return unique normalized CWEs (order preserved) from strings/ints/lists."""
    out: list[str] = []
    for v in _flatten(values):
        cwe = normalize_cwe(v)
        if cwe and cwe not in out:
            out.append(cwe)
    return out


def extract_cves(values: Iterable[Any]) -> list[str]:
    """Return unique upper-cased CVE ids (order preserved) found anywhere in the given strings."""
    out: list[str] = []
    for v in _flatten(values):
        if v is None:
            continue
        for m in CVE_RE.findall(str(v)):
            cve = m.upper()
            if cve not in out:
                out.append(cve)
    return out


def severity_from_cvss(score: Any) -> str | None:
    """Map a numeric CVSS / SARIF security-severity score to critical/high/medium/low."""
    try:
        val = float(score)
    except (TypeError, ValueError):
        return None
    if val >= 9.0:
        return "critical"
    if val >= 7.0:
        return "high"
    if val >= 4.0:
        return "medium"
    return "low"


def short_hash(*parts: Any, length: int = 16) -> str:
    """Deterministic short hash of the given parts."""
    payload = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]


def safe_id(value: str, max_len: int = 120) -> str:
    """Make an id filesystem/markdown friendly."""
    cleaned = re.sub(r"[^A-Za-z0-9._:-]+", "_", value).strip("_")
    return cleaned[:max_len]


def dedupe_ids(findings: list) -> list:
    """Ensure every finding id is unique by suffixing repeats with _2, _3, ... (in order)."""
    used: set[str] = set()
    for f in findings:
        base, n, candidate = f.id, 1, f.id
        while candidate in used:
            n += 1
            candidate = f"{base}_{n}"
        f.id = candidate
        used.add(candidate)
    return findings


def _flatten(values: Iterable[Any]) -> Iterable[Any]:
    for v in values:
        if isinstance(v, list | tuple | set):
            yield from _flatten(v)
        else:
            yield v
