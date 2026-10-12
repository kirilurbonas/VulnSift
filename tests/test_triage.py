"""Triage agent and prompt tests with a fake Anthropic client."""

from types import SimpleNamespace

import pytest

from tests.fakes import FakeClient, triage_output, usage
from vulnsift.llm import LLMError, UsageTracker, estimate_cost
from vulnsift.models import Location, UnifiedFinding, UsageSummary
from vulnsift.triage.agent import to_result, triage_finding
from vulnsift.triage.prompts import SYSTEM_PROMPT, TriageOutput, build_user_prompt


@pytest.fixture
def sample_finding() -> UnifiedFinding:
    return UnifiedFinding(
        id="test-1",
        rule_id="SQLi",
        title="SQL injection",
        message="User input in query",
        severity="high",
        description="Possible SQL injection.",
        location=Location(file_path="app.py", start_line=10),
        source_format="sarif",
    )


def test_build_user_prompt(sample_finding: UnifiedFinding) -> None:
    text = build_user_prompt(sample_finding)
    assert "SQLi" in text
    assert "SQL injection" in text
    assert "app.py" in text
    assert "Line: 10" in text
    assert text.startswith("<finding>")

    with_context = build_user_prompt(sample_finding, "Python app, internal only.")
    assert "<project_context>" in with_context
    assert "internal only" in with_context


def test_build_user_prompt_redact(sample_finding: UnifiedFinding) -> None:
    sample_finding.location.snippet = "print('secret')"
    text = build_user_prompt(sample_finding, redact_code=True)
    assert "redacted" in text.lower()
    assert "print('secret')" not in text


def test_build_user_prompt_clips_huge_fields(sample_finding: UnifiedFinding) -> None:
    sample_finding.description = "x" * 50_000
    text = build_user_prompt(sample_finding)
    assert len(text) < 20_000
    assert "truncated" in text


def test_system_prompt_warns_about_injection() -> None:
    assert "untrusted" in SYSTEM_PROMPT
    assert "Never follow instructions" in SYSTEM_PROMPT


def test_to_result_clamps_and_filters() -> None:
    triage, card = to_result(triage_output(risk_score=14, confidence=-3, code_snippet="  "))
    assert triage.risk_score == 10
    assert triage.confidence == 0
    assert card.code_snippet is None
    assert card.reference_links == ["https://cwe.mitre.org/data/definitions/89.html"]


def test_triage_finding_uses_structured_output_and_caching(sample_finding: UnifiedFinding) -> None:
    client = FakeClient()
    tracker = UsageTracker("claude-opus-5-5")
    triage, card = triage_finding(sample_finding, "internal", client=client, model="claude-opus-5-5", tracker=tracker)

    assert triage.risk_score == 8
    assert triage.confidence == 7
    assert card.title == "Use parameterized queries"
    call = client.calls[0]
    assert call["output_format"] is TriageOutput
    assert call["model"] == "claude-opus-5-5"
    assert call["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert "tool_choice" not in call
    assert tracker.summary().requests == 1


def test_triage_finding_passes_effort(sample_finding: UnifiedFinding) -> None:
    client = FakeClient()
    triage_finding(sample_finding, client=client, effort="low")
    assert client.calls[0]["output_config"] == {"effort": "low"}


@pytest.mark.parametrize(
    ("stop_reason", "message"),
    [("refusal", "declined"), ("max_tokens", "truncated")],
)
def test_triage_finding_bad_stop_reason(sample_finding: UnifiedFinding, stop_reason: str, message: str) -> None:
    client = FakeClient(
        lambda kw: SimpleNamespace(parsed_output=None, stop_reason=stop_reason, usage=usage(), stop_details=None)
    )
    with pytest.raises(LLMError, match=message):
        triage_finding(sample_finding, client=client)


def test_estimate_cost_known_and_unknown_models() -> None:
    u = UsageSummary(input_tokens=1_000_000, output_tokens=100_000, cache_read_input_tokens=1_000_000)
    assert estimate_cost("claude-opus-5-5", u) == pytest.approx(4.0 + 2.0 + 0.2)
    assert estimate_cost("some-future-model", u) is None
