"""Lightweight CODEOWNERS parsing and ownership rollups."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath

from vulnsift.analytics import get_backlog_items
from vulnsift.models import HIGH_RISK_THRESHOLD, TriageReport

CODEOWNERS_CANDIDATES = (
    ".github/CODEOWNERS",
    "CODEOWNERS",
    "docs/CODEOWNERS",
)


@dataclass(frozen=True)
class CodeownersRule:
    """One CODEOWNERS rule."""

    pattern: str
    owners: tuple[str, ...]
    line_number: int


def find_codeowners(cwd: str | Path | None = None) -> Path | None:
    """Return the first standard CODEOWNERS path found in the working tree."""
    root = Path(cwd or ".").resolve()
    for candidate in CODEOWNERS_CANDIDATES:
        path = root / candidate
        if path.is_file():
            return path
    return None


def load_codeowners(
    path: str | Path | None = None,
    *,
    cwd: str | Path | None = None,
) -> tuple[list[CodeownersRule], Path | None]:
    """Load CODEOWNERS rules from an explicit path or a standard location."""
    resolved: Path | None
    if path is None:
        resolved = find_codeowners(cwd)
        if resolved is None:
            return [], None
    else:
        resolved = Path(path)
        if not resolved.is_absolute():
            resolved = (Path(cwd or ".").resolve() / resolved).resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"CODEOWNERS file not found: {resolved}")

    rules = parse_codeowners(resolved.read_text(encoding="utf-8"))
    return rules, resolved


def parse_codeowners(text: str) -> list[CodeownersRule]:
    """Parse a CODEOWNERS file into rules.

    Supports common path-prefix and glob rules. Later matching rules win.
    """
    rules: list[CodeownersRule] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        pattern = parts[0]
        if pattern.startswith("!"):
            continue
        owners = tuple(owner for owner in parts[1:] if owner)
        if not owners:
            continue
        rules.append(CodeownersRule(pattern=pattern, owners=owners, line_number=line_number))
    return rules


def owners_for_path(path: str, rules: list[CodeownersRule]) -> tuple[str, ...]:
    """Return the owners that match the path, using last-match-wins semantics."""
    normalized_path = _normalize_path(path)
    matched: tuple[str, ...] = ()
    for rule in rules:
        if _matches(rule.pattern, normalized_path):
            matched = rule.owners
    return matched


def summarize_by_owner(
    report: TriageReport,
    rules: list[CodeownersRule],
    *,
    min_risk: float = 0,
    limit: int | None = None,
    unowned_label: str = "(unowned)",
) -> list[dict[str, object]]:
    """Group actionable findings by owner set."""
    items = get_backlog_items(report, limit=None, min_risk=min_risk)
    grouped: dict[str, dict[str, object]] = {}

    for item in items:
        owners = owners_for_path(str(item["file_path"]), rules)
        owner_key = " ".join(owners) if owners else unowned_label
        row = grouped.get(owner_key)
        if row is None:
            row = {
                "owners": owner_key,
                "finding_count": 0,
                "high_risk_count": 0,
                "max_risk": 0,
                "total_risk": 0,
                "top_files": set(),
                "top_rules": set(),
            }
            grouped[owner_key] = row
        row["finding_count"] = int(row["finding_count"]) + 1
        is_high = float(item["risk_score"]) >= HIGH_RISK_THRESHOLD
        row["high_risk_count"] = int(row["high_risk_count"]) + (1 if is_high else 0)
        row["max_risk"] = max(int(row["max_risk"]), int(item["risk_score"]))
        row["total_risk"] = int(row["total_risk"]) + int(item["risk_score"])
        row["top_files"].add(str(item["file_path"]))
        row["top_rules"].add(str(item["rule_id"]))

    rows: list[dict[str, object]] = []
    for row in grouped.values():
        finding_count = int(row["finding_count"])
        total_risk = int(row["total_risk"])
        rows.append(
            {
                "owners": row["owners"],
                "finding_count": finding_count,
                "high_risk_count": row["high_risk_count"],
                "max_risk": row["max_risk"],
                "total_risk": total_risk,
                "avg_risk": round(total_risk / finding_count, 1) if finding_count else 0.0,
                "top_files": sorted(row["top_files"])[:3],
                "top_rules": sorted(row["top_rules"])[:3],
            }
        )

    rows.sort(
        key=lambda item: (
            -int(item["total_risk"]),
            -int(item["high_risk_count"]),
            -int(item["finding_count"]),
            str(item["owners"]),
        )
    )
    if limit is None:
        return rows
    return rows[: max(limit, 0)]


def annotate_backlog_owners(
    rows: list[dict[str, object]],
    rules: list[CodeownersRule],
    *,
    unowned_label: str = "(unowned)",
) -> list[dict[str, object]]:
    """Annotate backlog-style rows with CODEOWNERS ownership."""
    annotated: list[dict[str, object]] = []
    for row in rows:
        owners = owners_for_path(str(row.get("file_path", "")), rules)
        owner_key = " ".join(owners) if owners else unowned_label
        enriched = dict(row)
        enriched["owners"] = owner_key
        annotated.append(enriched)
    return annotated


def _normalize_path(path: str) -> str:
    value = path.replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    value = value.lstrip("/")
    return str(PurePosixPath(value)) if value else ""


@lru_cache(maxsize=1024)
def _pattern_regex(pattern: str) -> re.Pattern[str] | None:
    """Translate a CODEOWNERS (gitignore-style) pattern into a regex over repo-relative paths.

    - A leading "/" or any inner "/" anchors the pattern to the repository root;
      otherwise it matches at any depth (e.g. "docs" matches "a/docs/x").
    - "*" and "?" never cross "/"; "**" does.
    - A pattern that matches a directory also matches everything below it.
    """
    pat = pattern.strip().replace("\\", "/")
    if not pat or pat.startswith("!"):
        return None
    dir_only = pat.endswith("/")
    anchored = pat.startswith("/") or "/" in pat.strip("/")
    pat = pat.strip("/")
    if not pat:
        return None

    out: list[str] = []
    i = 0
    while i < len(pat):
        c = pat[i]
        if c == "*":
            if pat[i : i + 2] == "**":
                i += 2
                if pat[i : i + 1] == "/":
                    out.append("(?:.*/)?")
                    i += 1
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                out.append(pat[i : j + 1])
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    body = "".join(out)
    prefix = "" if anchored else "(?:.*/)?"
    suffix = "/.*" if dir_only else "(?:/.*)?"
    try:
        return re.compile(f"^{prefix}{body}{suffix}$")
    except re.error:
        return None


def _matches(pattern: str, path: str) -> bool:
    regex = _pattern_regex(pattern)
    return bool(regex and path and regex.match(path))
