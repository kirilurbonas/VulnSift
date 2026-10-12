"""SARIF 2.1.0 parser -> list of UnifiedFinding.

Works with SARIF from Semgrep, CodeQL, Snyk Code, Trivy, Checkov, etc. Resolves file paths from
``artifactLocation.uri`` (falling back to ``run.artifacts[index]``), rules via ``ruleId`` /
``ruleIndex`` / ``rule`` (including ``tool.extensions``), and severity from ``security-severity``
(GitHub convention) before falling back to the SARIF ``level``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from vulnsift.models import Location, UnifiedFinding
from vulnsift.parsers._common import (
    dedupe_ids,
    extract_cves,
    extract_cwes,
    load_json,
    safe_id,
    severity_from_cvss,
    short_hash,
)

SARIF_LEVELS = ("error", "warning", "note", "none")
# Result kinds that are not actual problems (SARIF 3.27.9).
_NON_FINDING_KINDS = ("pass", "notapplicable")
_MAX_HELP_CHARS = 4000


def parse_sarif(path: str | Path) -> list[UnifiedFinding]:
    """
    Parse a SARIF 2.1.0 file into a list of UnifiedFinding.
    Fails fast with clear errors on invalid or unsupported format.
    """
    data = load_json(path, "SARIF")

    if not isinstance(data, dict):
        raise ValueError("SARIF root must be a JSON object")

    version = data.get("version") or data.get("$schema", "")
    if "2.1" not in str(version) and "sarif" not in str(version).lower():
        raise ValueError(f"Unsupported SARIF version: {version}. VulnSift expects SARIF 2.1.0.")

    runs = data.get("runs")
    if not runs or not isinstance(runs, list):
        return []

    findings: list[UnifiedFinding] = []
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            continue
        ctx = _RunContext(run, run_index)
        results = run.get("results") or []
        if not isinstance(results, list):
            continue
        for res_index, result in enumerate(results):
            if not isinstance(result, dict):
                continue
            if str(result.get("kind") or "fail").lower() in _NON_FINDING_KINDS:
                continue
            findings.append(_result_to_finding(result, res_index, ctx))

    return dedupe_ids(findings)


class _RunContext:
    """Per-run lookup tables: rules (driver + extensions), artifacts, uriBaseIds."""

    def __init__(self, run: dict, run_index: int) -> None:
        self.run_index = run_index
        tool = _as_dict(run.get("tool"))
        driver = _as_dict(tool.get("driver"))
        self.tool_name = str(driver.get("name") or "")
        self.driver_rules: list = _as_list(driver.get("rules"))
        self.extension_rules: list[list] = [
            _as_list(_as_dict(ext).get("rules")) for ext in _as_list(tool.get("extensions"))
        ]
        self.rules_by_id: dict[str, dict] = {}
        for rules in [self.driver_rules, *self.extension_rules]:
            for r in rules:
                if isinstance(r, dict) and r.get("id"):
                    self.rules_by_id.setdefault(str(r["id"]), r)
        self.artifacts: list = _as_list(run.get("artifacts"))
        self.base_ids: dict = _as_dict(run.get("originalUriBaseIds"))

    def find_rule(self, result: dict) -> dict:
        rule_ref = _as_dict(result.get("rule"))
        # Explicit index (result.rule.index + optional toolComponent, or result.ruleIndex) wins.
        idx = rule_ref.get("index", result.get("ruleIndex"))
        if isinstance(idx, int) and idx >= 0:
            rules = self.driver_rules
            comp = _as_dict(rule_ref.get("toolComponent"))
            comp_idx = comp.get("index")
            if isinstance(comp_idx, int) and 0 <= comp_idx < len(self.extension_rules):
                rules = self.extension_rules[comp_idx]
            if idx < len(rules) and isinstance(rules[idx], dict):
                return rules[idx]
        rule_id = result.get("ruleId") or rule_ref.get("id")
        if rule_id:
            rule_id = str(rule_id)
            if rule_id in self.rules_by_id:
                return self.rules_by_id[rule_id]
            # Hierarchical ids ("CA2101/1") refer to the parent rule.
            parent = rule_id.split("/")[0]
            if parent in self.rules_by_id:
                return self.rules_by_id[parent]
        return {}

    def resolve_uri(self, artifact_location: dict) -> str:
        """Resolve an artifactLocation to a file path (relative paths stay relative)."""
        art = _as_dict(artifact_location)
        uri = art.get("uri")
        base_id = art.get("uriBaseId")
        idx = art.get("index")
        if not uri and isinstance(idx, int) and 0 <= idx < len(self.artifacts):
            art_loc = _as_dict(_as_dict(self.artifacts[idx]).get("location"))
            uri = art_loc.get("uri")
            base_id = base_id or art_loc.get("uriBaseId")
        if not uri:
            return ""
        return self._apply_base(str(uri), base_id, depth=0)

    def _apply_base(self, uri: str, base_id: Any, depth: int) -> str:
        if _is_absolute_uri(uri) or not base_id or depth > 5:
            return _uri_to_path(uri)
        base = _as_dict(self.base_ids.get(str(base_id)))
        base_uri = base.get("uri")
        # Only prefix relative bases (e.g. "src/"); an absolute base such as file:///home/ci/repo/
        # (or %SRCROOT%) is the checkout root, so the repo-relative uri is kept as-is.
        if not base_uri or _is_absolute_uri(str(base_uri)):
            return _uri_to_path(uri)
        prefix = self._apply_base(str(base_uri), base.get("uriBaseId"), depth + 1)
        if prefix and not prefix.endswith("/"):
            prefix += "/"
        return _uri_to_path(prefix + uri)


def _is_absolute_uri(uri: str) -> bool:
    scheme = urlparse(uri).scheme
    # len > 1 so a Windows drive letter ("C:/src") is not mistaken for a scheme.
    return len(scheme) > 1 or uri.startswith("/") or (len(uri) > 2 and uri[1] == ":" and uri[2] in "/\\")


def _uri_to_path(uri: str) -> str:
    """Strip file:// and percent-encoding; leave other schemes and relative paths alone."""
    if uri.lower().startswith("file:"):
        parsed = urlparse(uri)
        path = unquote(parsed.path)
        # file:///C:/x -> /C:/x on Windows-produced SARIF
        if len(path) > 2 and path[0] == "/" and path[2] == ":":
            path = path[1:]
        return path
    if "://" in uri:
        return uri
    path = unquote(uri)
    return path[2:] if path.startswith("./") else path


def _get_message(obj: Any, rule: dict | None = None) -> str:
    """Extract message text from a SARIF message / multiformatMessageString object."""
    if not isinstance(obj, dict):
        return str(obj) if obj else ""
    text = obj.get("text") or obj.get("markdown") or ""
    if not text and rule and obj.get("id"):
        # message.id references rule.messageStrings[id]
        text = _get_message(_as_dict(rule.get("messageStrings")).get(obj["id"]))
    if text and isinstance(obj.get("arguments"), list):
        for i, arg in enumerate(obj["arguments"]):
            text = text.replace("{" + str(i) + "}", str(arg))
    return str(text)


def _result_to_finding(result: dict, res_index: int, ctx: _RunContext) -> UnifiedFinding:
    rule = ctx.find_rule(result)
    rule_ref = _as_dict(result.get("rule"))
    rule_id = str(result.get("ruleId") or rule_ref.get("id") or rule.get("id") or "")
    rule_props = _as_dict(rule.get("properties"))
    result_props = _as_dict(result.get("properties"))

    short_desc = _get_message(rule.get("shortDescription"))
    full_desc = _get_message(rule.get("fullDescription"))
    help_text = _get_message(rule.get("help"))
    msg = _get_message(result.get("message"), rule) or short_desc or full_desc or rule_id or "Finding"
    title = short_desc
    if not title or title == rule_id or title.startswith("Semgrep Finding:"):
        # Semgrep emits "Semgrep Finding: <rule id>" as shortDescription; the message is more useful.
        title = msg.splitlines()[0] if msg else str(rule.get("name") or rule_id)

    description = full_desc or short_desc
    if help_text and help_text.strip() != description.strip():
        help_text = help_text[:_MAX_HELP_CHARS]
        description = f"{description}\n\n{help_text}" if description else help_text

    severity = _severity(result, rule, result_props, rule_props)

    tags = [*_as_list(rule_props.get("tags")), *_as_list(result_props.get("tags"))]
    cwes = extract_cwes([*tags, rule_props.get("cwe"), result_props.get("cwe")])
    cves = extract_cves([rule_id, rule.get("name"), *tags, msg, short_desc])

    loc = _location(result, ctx)
    finding_id = _finding_id(result, rule_id, loc, msg, ctx, res_index)

    raw = dict(result)
    if ctx.tool_name:
        raw["tool_name"] = ctx.tool_name
    if cwes:
        raw["cwes"] = cwes
    if cves:
        raw["cves"] = cves
    help_uri = rule.get("helpUri")
    if help_uri:
        raw["references"] = [help_uri]

    return UnifiedFinding(
        id=finding_id,
        rule_id=rule_id,
        title=title[:200],
        message=msg,
        severity=severity,
        description=description,
        cve=cves[0] if cves else None,
        cwe=cwes[0] if cwes else None,
        location=loc,
        raw=raw,
        source_format="sarif",
    )


def _severity(result: dict, rule: dict, result_props: dict, rule_props: dict) -> str:
    """security-severity (CVSS-like) wins; else result.level, rule default level, 'warning'."""
    for props in (result_props, rule_props):
        sev = severity_from_cvss(props.get("security-severity"))
        if sev:
            return sev
    level = str(result.get("level") or "").lower()
    if level not in SARIF_LEVELS:
        default_cfg = _as_dict(rule.get("defaultConfiguration"))
        level = str(default_cfg.get("level") or "").lower()
    return level if level in SARIF_LEVELS else "warning"


def _location(result: dict, ctx: _RunContext) -> Location:
    loc = Location()
    locations = _as_list(result.get("locations"))
    first = _as_dict(locations[0]) if locations else {}
    ploc = _as_dict(first.get("physicalLocation"))
    if ploc:
        loc.file_path = ctx.resolve_uri(_as_dict(ploc.get("artifactLocation")))
        if not loc.file_path and isinstance(ploc.get("artifactIndex"), int):
            # Non-standard but seen in the wild: physicalLocation.artifactIndex
            loc.file_path = ctx.resolve_uri({"index": ploc["artifactIndex"]})
        region = _as_dict(ploc.get("region"))
        context_region = _as_dict(ploc.get("contextRegion"))
        start = region.get("startLine")
        loc.start_line = start if isinstance(start, int) else None
        end = region.get("endLine")
        loc.end_line = end if isinstance(end, int) else loc.start_line
        snippet = _as_dict(region.get("snippet")).get("text") or _as_dict(context_region.get("snippet")).get("text")
        loc.snippet = snippet or None
    logical = [_as_dict(x) for x in _as_list(first.get("logicalLocations"))]
    names = [x.get("fullyQualifiedName") or x.get("name") for x in logical]
    names = [str(n) for n in names if n]
    if names:
        loc.region = names[0]
    return loc


def _finding_id(result: dict, rule_id: str, loc: Location, msg: str, ctx: _RunContext, res_index: int) -> str:
    """Stable id: prefer scanner fingerprints, else a hash of rule + location + message."""
    for key in ("fingerprints", "partialFingerprints"):
        fps = _as_dict(result.get(key))
        if fps:
            # Some fingerprints (CodeQL primaryLocationLineHash) are line-content hashes, so mix in the path.
            name = sorted(fps)[0]
            return safe_id(f"sarif_{rule_id}_{short_hash(rule_id, loc.file_path, name, fps[name])}")
    if result.get("guid"):
        return safe_id(f"sarif_{rule_id}_{short_hash(rule_id, result['guid'])}")
    if not loc.file_path and loc.start_line is None:
        # No location: fall back to position so distinct results don't collapse.
        return safe_id(f"sarif_{rule_id}_{short_hash(ctx.run_index, res_index, rule_id, msg)}")
    locations = _as_list(result.get("locations"))
    first = _as_dict(locations[0]) if locations else {}
    region = _as_dict(_as_dict(first.get("physicalLocation")).get("region"))
    return safe_id(
        f"sarif_{rule_id}_{short_hash(rule_id, loc.file_path, loc.start_line, region.get('startColumn'), msg)}"
    )


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []
