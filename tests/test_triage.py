"""Triage agent tests with mocked Anthropic client."""

from unittest.mock import MagicMock, patch

import pytest

from vulnsift.models import Location, UnifiedFinding
from vulnsift.triage.agent import _parse_tool_use, triage_finding
from vulnsift.triage.prompts import build_user_prompt


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
    assert "10" in text

    with_context = build_user_prompt(sample_finding, "Python app, internal only.")
    assert "Project context" in with_context
    assert "internal only" in with_context


def test_build_user_prompt_redact(sample_finding: UnifiedFinding) -> None:
    sample_finding.location.snippet = "print('secret')"  # type: ignore[assignment]
    text = build_user_prompt(sample_finding, redact_code=True)
    assert "redacted" in text.lower()
    assert "print('secret')" not in text


def test_parse_tool_use() -> None:
    class Block:
        type = "tool_use"
        name = "submit_triage"
        input = {
            "risk_score": 8,
            "is_likely_false_positive": False,
            "reasoning": "User input flows to query.",
            "exploitability_notes": "Reachable from web.",
            "remediation_title": "Use parameterized queries",
            "business_impact": "Data breach risk.",
            "remediation_steps": ["Use cursor.execute with params.", "Never concatenate."],
            "code_snippet": "cursor.execute('SELECT * FROM t WHERE id=%s', (id,))",
            "reference_links": ["https://example.com/sqli"],
        }

    class Response:
        content = [Block()]

    triage, card = _parse_tool_use(Response())
    assert triage.risk_score == 8
    assert triage.is_likely_false_positive is False
    assert "User input" in triage.reasoning
    assert card.title == "Use parameterized queries"
    assert len(card.steps) == 2
    assert card.code_snippet is not None
    assert len(card.reference_links) == 1


def test_triage_finding_mock(sample_finding: UnifiedFinding) -> None:
    """Call triage_finding with mocked API returning tool_use."""
    mock_input = {
        "risk_score": 5,
        "is_likely_false_positive": True,
        "reasoning": "Test reasoning",
        "exploitability_notes": "",
        "remediation_title": "Test fix",
        "business_impact": "Low",
        "remediation_steps": ["Step 1"],
        "code_snippet": None,
        "reference_links": [],
    }

    mock_content = MagicMock()
    mock_content.type = "tool_use"
    mock_content.name = "submit_triage"
    mock_content.input = mock_input

    mock_response = MagicMock()
    mock_response.content = [mock_content]

    with patch("vulnsift.triage.agent.Anthropic") as MockAnthropic:
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        MockAnthropic.return_value = mock_client

        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            triage, card = triage_finding(sample_finding)

    assert triage.risk_score == 5
    assert triage.is_likely_false_positive is True
    assert card.title == "Test fix"


def test_triage_finding_no_api_key(sample_finding: UnifiedFinding) -> None:
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            triage_finding(sample_finding)
