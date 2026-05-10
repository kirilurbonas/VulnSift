"""Tests for triage cache fingerprint and persistence."""

from __future__ import annotations

import json
from pathlib import Path

from vulnsift.models import Location, RemediationCard, TriageReportEntry, TriageResult, UnifiedFinding
from vulnsift.triage import cache as triage_cache


def test_fingerprint_stable() -> None:
    f = UnifiedFinding(
        id="a",
        rule_id="R1",
        title="t",
        message="m",
        severity="high",
        location=Location(file_path="x.py", start_line=1, snippet="code"),
        source_format="sarif",
    )
    fp1 = triage_cache.fingerprint(f, "1.0", False)
    fp2 = triage_cache.fingerprint(f, "1.0", False)
    assert fp1 == fp2
    assert fp1 != triage_cache.fingerprint(f, "1.0", True)


def test_cache_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    finding = UnifiedFinding(
        id="id1",
        rule_id="SQLi",
        title="SQL",
        message="msg",
        severity="high",
        location=Location(file_path="app.py", start_line=10),
        source_format="sarif",
    )
    entry = TriageReportEntry(
        finding=finding,
        triage=TriageResult(risk_score=8, is_likely_false_positive=False, reasoning="r"),
        remediation=RemediationCard(title="fix", business_impact="b", steps=["1"]),
    )
    fp = triage_cache.fingerprint(finding, "1.0", False)
    data = {fp: triage_cache.report_entry_to_cache_dict(entry)}
    triage_cache.save_cache(path, data, "1.0")
    loaded = triage_cache.load_cache(path, "1.0")
    assert fp in loaded
    restored = triage_cache.cache_entry_to_report_entry(finding, loaded[fp])
    assert restored is not None
    assert restored.triage.risk_score == 8
    assert restored.remediation is not None
    assert restored.remediation.title == "fix"


def test_cache_invalidated_on_prompt_version(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    path.write_text(
        json.dumps(
            {"file_version": "1", "prompt_version": "0.9", "entries": {"k": {"triage": {}, "remediation": None}}}
        ),
        encoding="utf-8",
    )
    assert triage_cache.load_cache(path, "1.0") == {}
