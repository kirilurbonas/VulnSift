"""Snyk JSON parser -> list of UnifiedFinding.

Supports ``snyk test --json`` for a single project (top-level object) and ``--all-projects`` /
multi-target output (top-level list of project objects). Snyk repeats a vulnerability once per
dependency path; those repeats are merged into one finding per (vuln id, package, version).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnsift.models import Location, UnifiedFinding
from vulnsift.parsers._common import dedupe_ids, extract_cves, extract_cwes, load_json, safe_id

_MAX_PATHS_IN_MESSAGE = 5


def parse_snyk(path: str | Path) -> list[UnifiedFinding]:
    """
    Parse Snyk test --json output into a list of UnifiedFinding.
    Accepts a single project object or a list of project objects (--all-projects).
    """
    data = load_json(path, "Snyk")

    if isinstance(data, dict):
        projects = [data]
        if "vulnerabilities" not in data and data.get("error"):
            raise ValueError(f"Snyk output contains an error instead of results: {data.get('error')}")
    elif isinstance(data, list):
        projects = [p for p in data if isinstance(p, dict)]
    else:
        raise ValueError("Snyk root must be a JSON object or a list of project objects")

    findings: list[UnifiedFinding] = []
    for project_index, project in enumerate(projects):
        findings.extend(_parse_project(project, project_index, multi=len(projects) > 1))
    return dedupe_ids(findings)


def _parse_project(project: dict, project_index: int, multi: bool) -> list[UnifiedFinding]:
    vulnerabilities = project.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        return []

    target_file = str(project.get("displayTargetFile") or project.get("targetFile") or project.get("path") or "")
    project_name = str(project.get("projectName") or "")
    project_key = target_file or project_name or (f"project{project_index}" if multi else "")

    # Group repeats of the same vuln (one per dependency path) preserving first-seen order.
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        key = (str(vuln.get("id") or vuln.get("title") or ""), _package_name(vuln), _version(vuln))
        groups.setdefault(key, []).append(vuln)

    return [
        _vulns_to_finding(group, target_file, project_name, project_key, project.get("packageManager"))
        for group in groups.values()
    ]


def _package_name(vuln: dict) -> str:
    return str(vuln.get("packageName") or vuln.get("moduleName") or vuln.get("name") or "")


def _version(vuln: dict) -> str:
    version = vuln.get("version")
    if version:
        return str(version)
    semver = vuln.get("semver")
    if isinstance(semver, dict):
        vulnerable = semver.get("vulnerable") or []
        if isinstance(vulnerable, list) and vulnerable:
            return str(vulnerable[0])
    return ""


def _dep_path(vuln: dict) -> str:
    from_val = vuln.get("from")
    if isinstance(from_val, list):
        return " > ".join(str(p) for p in from_val)
    return str(from_val) if from_val else ""


def _vulns_to_finding(
    group: list[dict],
    target_file: str,
    project_name: str,
    project_key: str,
    package_manager: Any,
) -> UnifiedFinding:
    vuln = group[0]
    vuln_id = str(vuln.get("id") or "")
    title = vuln.get("title") or vuln_id
    if isinstance(title, dict):
        title = title.get("title", str(title))
    title = str(title).strip() or "Snyk finding"

    description = vuln.get("description") or ""
    if isinstance(description, list):
        description = " ".join(str(d) for d in description)
    description = str(description).strip()

    severity = str(vuln.get("severity") or "medium").lower()
    package_name = _package_name(vuln)
    version = _version(vuln)
    pkg_ref = f"{package_name}@{version}" if version else package_name

    identifiers = vuln.get("identifiers") if isinstance(vuln.get("identifiers"), dict) else {}
    cves = extract_cves([identifiers.get("CVE") or [], vuln_id])
    cwes = extract_cwes([identifiers.get("CWE") or []])

    dep_paths: list[str] = []
    for v in group:
        p = _dep_path(v)
        if p and p not in dep_paths:
            dep_paths.append(p)

    fixed_in = [str(x) for x in (vuln.get("fixedIn") or []) if x] if isinstance(vuln.get("fixedIn"), list) else []
    upgrade_paths: list[str] = []
    for v in group:
        up = v.get("upgradePath")
        if isinstance(up, list) and any(up):
            upgrade = " > ".join(str(x) for x in up if x)
            if upgrade not in upgrade_paths:
                upgrade_paths.append(upgrade)

    if not pkg_ref:
        message = title
    elif package_name and package_name in title:
        message = f"{title} ({pkg_ref})"
    else:
        message = f"{title} in {pkg_ref}"
    if dep_paths:
        shown = dep_paths[:_MAX_PATHS_IN_MESSAGE]
        more = len(dep_paths) - len(shown)
        message += ". Introduced through: " + "; ".join(shown)
        if more > 0:
            message += f" (and {more} more path(s))"

    extra_lines: list[str] = []
    if fixed_in:
        extra_lines.append(f"Fixed in: {', '.join(fixed_in)}")
    if upgrade_paths:
        extra_lines.append(f"Upgrade path: {upgrade_paths[0]}")
    elif vuln.get("isUpgradable") is False and vuln.get("isPatchable") is False and not fixed_in:
        extra_lines.append("No fix available.")
    if vuln.get("cvssScore") is not None:
        extra_lines.append(f"CVSS score: {vuln.get('cvssScore')}")
    references = _references(vuln)
    if extra_lines:
        description = (description + "\n\n" if description else "") + "\n".join(extra_lines)

    loc = Location(file_path=target_file, region=dep_paths[0] if dep_paths else None)

    raw = dict(vuln)
    raw.update(
        {
            "occurrences": len(group),
            "paths": dep_paths,
            "fixed_in": fixed_in,
            "upgrade_paths": upgrade_paths,
            "references": references,
            "cves": cves,
            "cwes": cwes,
            "target_file": target_file,
            "project_name": project_name,
            "package_manager": package_manager,
        }
    )

    id_parts = ["snyk", project_key, vuln_id or title[:30], pkg_ref]
    unique_id = safe_id("_".join(p for p in id_parts if p), max_len=160)
    return UnifiedFinding(
        id=unique_id,
        rule_id=vuln_id,
        title=title,
        message=message,
        severity=severity,
        description=description,
        cve=cves[0] if cves else None,
        cwe=cwes[0] if cwes else None,
        location=loc,
        raw=raw,
        source_format="snyk",
    )


def _references(vuln: dict) -> list[str]:
    out: list[str] = []
    refs = vuln.get("references")
    for ref in refs if isinstance(refs, list) else []:
        url = ref.get("url") if isinstance(ref, dict) else ref
        if url and str(url) not in out:
            out.append(str(url))
    return out
