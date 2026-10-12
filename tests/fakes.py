"""Test doubles for the Anthropic client (no network)."""

from __future__ import annotations

import threading
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

from vulnsift.triage.prompts import TriageOutput


def triage_output(**overrides: Any) -> TriageOutput:
    data: dict[str, Any] = {
        "risk_score": 8,
        "is_likely_false_positive": False,
        "confidence": 7,
        "reasoning": "User input reaches the query.",
        "exploitability_notes": "Reachable from an unauthenticated endpoint.",
        "remediation_title": "Use parameterized queries",
        "business_impact": "Database exfiltration.",
        "remediation_steps": ["Use bound parameters.", "Add a regression test."],
        "code_snippet": "cursor.execute('SELECT 1 WHERE id=%s', (x,))",
        "reference_links": ["https://cwe.mitre.org/data/definitions/89.html", "not-a-url"],
    }
    data.update(overrides)
    return TriageOutput(**data)


def usage(input_tokens: int = 1000, output_tokens: int = 200, cache_read: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read_input_tokens=cache_read,
        cache_creation_input_tokens=0,
    )


class FakeClient:
    """Mimics `anthropic.Anthropic().messages.parse` with a programmable responder."""

    def __init__(self, responder: Callable[[dict[str, Any]], Any] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._responder = responder or (lambda kwargs: triage_output())
        self.messages = SimpleNamespace(parse=self._parse)

    def _parse(self, **kwargs: Any) -> SimpleNamespace:
        with self._lock:
            self.calls.append(kwargs)
        result = self._responder(kwargs)
        if isinstance(result, BaseException):
            raise result
        if isinstance(result, SimpleNamespace):
            return result
        return SimpleNamespace(parsed_output=result, stop_reason="end_turn", usage=usage(), stop_details=None)


def api_error(cls: type, status: int, message: str = "error") -> Exception:
    """Build a real anthropic APIStatusError subclass instance."""
    import httpx2

    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    return cls(message, response=httpx2.Response(status, request=request), body=None)
