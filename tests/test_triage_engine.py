"""Concurrent triage engine: dedupe, caching, error isolation, fatal errors."""

import json
from pathlib import Path

import anthropic
import pytest

from tests.fakes import FakeClient, api_error, triage_output
from vulnsift.models import Location, UnifiedFinding
from vulnsift.triage.engine import FatalTriageError, TriageOptions, run_triage


def _finding(i: int, *, snippet: str | None = None, line: int | None = None) -> UnifiedFinding:
    return UnifiedFinding(
        id=f"f{i}",
        rule_id=f"rule-{i}",
        title=f"Finding {i}",
        severity="high",
        location=Location(file_path=f"src/m{i}.py", start_line=line or i, snippet=snippet),
        source_format="sarif",
    )


def test_results_keep_input_order_with_concurrency() -> None:
    findings = [_finding(i) for i in range(20)]

    def responder(kwargs):
        rule = kwargs["messages"][0]["content"].split("Rule/ID: ")[1].split("\n")[0]
        return triage_output(risk_score=int(rule.split("-")[1]) % 11)

    entries, stats = run_triage(findings, client=FakeClient(responder), options=TriageOptions(concurrency=8))
    assert [e.finding.id for e in entries] == [f.id for f in findings]
    assert [e.triage.risk_score for e in entries] == [i % 11 for i in range(20)]
    assert stats.api_calls == 20


def test_duplicates_are_triaged_once() -> None:
    a = _finding(1, line=10)
    b = a.model_copy(update={"id": "f1-dup", "location": Location(file_path="src/m1.py", start_line=99)})
    client = FakeClient()
    entries, stats = run_triage([a, b], client=client, options=TriageOptions())
    assert len(client.calls) == 1
    assert stats.duplicates == 1
    assert [e.finding.id for e in entries] == ["f1", "f1-dup"]
    assert entries[1].finding.location.start_line == 99
    assert entries[1].triage.risk_score == entries[0].triage.risk_score


def test_errors_are_isolated_and_not_false_positives() -> None:
    findings = [_finding(i) for i in range(3)]

    def responder(kwargs):
        if "rule-1" in kwargs["messages"][0]["content"]:
            return api_error(anthropic.InternalServerError, 500, "overloaded")
        return triage_output()

    seen: list[str] = []
    entries, stats = run_triage(
        findings, client=FakeClient(responder), options=TriageOptions(), on_result=lambda e, s: seen.append(s)
    )
    errored = [e for e in entries if e.triage.is_error]
    assert len(errored) == 1
    assert errored[0].finding.id == "f1"
    assert errored[0].triage.is_likely_false_positive is False
    assert not errored[0].is_actionable
    assert "500" in (errored[0].triage.error or "")
    assert stats.errors == 1
    assert sorted(seen) == ["error", "triaged", "triaged"]


def test_auth_error_aborts_run() -> None:
    client = FakeClient(lambda kw: api_error(anthropic.AuthenticationError, 401, "bad key"))
    with pytest.raises(FatalTriageError, match="authentication"):
        run_triage([_finding(i) for i in range(5)], client=client, options=TriageOptions(concurrency=2))


def test_cache_roundtrip_skips_api_and_ignores_line_moves(tmp_path: Path) -> None:
    cache = tmp_path / "cache.json"
    findings = [_finding(i, snippet=f"code {i}") for i in range(3)]
    client = FakeClient()
    run_triage(findings, client=client, options=TriageOptions(), cache_path=cache)
    assert len(client.calls) == 3
    assert json.loads(cache.read_text())["entries"]

    moved = [f.model_copy(update={"location": f.location.model_copy(update={"start_line": 500})}) for f in findings]
    client2 = FakeClient()
    entries, stats = run_triage(moved, client=client2, options=TriageOptions(), cache_path=cache)
    assert client2.calls == []
    assert stats.cache_hits == 3
    assert entries[0].finding.location.start_line == 500


def test_cache_invalidated_by_model_and_context(tmp_path: Path) -> None:
    cache = tmp_path / "cache.json"
    findings = [_finding(1)]
    run_triage(findings, client=FakeClient(), options=TriageOptions(model="m1"), cache_path=cache)

    c2 = FakeClient()
    run_triage(findings, client=c2, options=TriageOptions(model="m2"), cache_path=cache)
    assert len(c2.calls) == 1

    c3 = FakeClient()
    run_triage(findings, client=c3, options=TriageOptions(model="m1", project_context="public"), cache_path=cache)
    assert len(c3.calls) == 1


def test_errors_are_not_cached(tmp_path: Path) -> None:
    cache = tmp_path / "cache.json"
    failing = FakeClient(lambda kw: api_error(anthropic.InternalServerError, 503))
    run_triage([_finding(1)], client=failing, options=TriageOptions(), cache_path=cache)

    retry = FakeClient()
    entries, _ = run_triage([_finding(1)], client=retry, options=TriageOptions(), cache_path=cache)
    assert len(retry.calls) == 1
    assert not entries[0].triage.is_error
