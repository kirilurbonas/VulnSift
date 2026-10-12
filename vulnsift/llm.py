"""Shared Claude API plumbing: client creation, structured calls, usage and cost tracking."""

from __future__ import annotations

import os
import threading
from typing import TypeVar

import anthropic
from pydantic import BaseModel

from vulnsift.models import UsageSummary

DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_MAX_RETRIES = 4  # SDK retries 408/409/429/5xx and connection errors with exponential backoff.

# USD per million tokens: (input, output, cache read). Cache writes are billed at 1.25x input.
MODEL_PRICING: dict[str, tuple[float, float, float]] = {
    "claude-fable-5-1": (10.00, 50.00, 0.25),
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-opus-5": (5.00, 25.00, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20),
    "claude-sonnet-5": (2.00, 10.00, 0.20),
    "claude-sonnet-4-6": (3.00, 15.00, 0.30),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
    "claude-haiku-4-5": (1.00, 5.00, 0.10),
}

T = TypeVar("T", bound=BaseModel)


class LLMError(RuntimeError):
    """The model call completed but did not produce a usable result."""


def make_client(api_key: str | None = None, *, max_retries: int = DEFAULT_MAX_RETRIES) -> anthropic.Anthropic:
    """Create one client to share across calls (it is thread-safe and pools connections)."""
    key = api_key or os.environ.get("ANTHROPIC_API_KEY") or None
    return anthropic.Anthropic(api_key=key, max_retries=max_retries)


def estimate_cost(model: str, usage: UsageSummary) -> float | None:
    """Estimated USD cost for the given usage, or None for models without a known price."""
    pricing = MODEL_PRICING.get(model)
    if pricing is None:
        return None
    inp, out, cache_read = pricing
    total = (
        usage.input_tokens * inp
        + usage.output_tokens * out
        + usage.cache_read_input_tokens * cache_read
        + usage.cache_creation_input_tokens * inp * 1.25
    )
    return round(total / 1_000_000, 4)


class UsageTracker:
    """Thread-safe accumulator of API usage across many calls."""

    def __init__(self, model: str) -> None:
        self.model = model
        self._lock = threading.Lock()
        self._usage = UsageSummary()

    def add(self, usage: object | None) -> None:
        if usage is None:
            return
        with self._lock:
            u = self._usage
            u.requests += 1
            u.input_tokens += int(getattr(usage, "input_tokens", 0) or 0)
            u.output_tokens += int(getattr(usage, "output_tokens", 0) or 0)
            u.cache_read_input_tokens += int(getattr(usage, "cache_read_input_tokens", 0) or 0)
            u.cache_creation_input_tokens += int(getattr(usage, "cache_creation_input_tokens", 0) or 0)

    def summary(self) -> UsageSummary:
        with self._lock:
            snapshot = self._usage.model_copy()
        snapshot.estimated_cost_usd = estimate_cost(self.model, snapshot)
        return snapshot


def structured_call(
    client: anthropic.Anthropic,
    *,
    model: str,
    system: str,
    user: str,
    output_type: type[T],
    max_tokens: int = 16000,
    effort: str | None = None,
    tracker: UsageTracker | None = None,
) -> T:
    """Make one request whose answer is validated against `output_type` (structured outputs).

    The system prompt is marked cacheable: it is identical for every finding, so after the first
    request it is served from the prompt cache.
    """
    kwargs: dict = {}
    if effort:
        kwargs["output_config"] = {"effort": effort}
    response = client.messages.parse(
        model=model,
        max_tokens=max_tokens,
        system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": user}],
        output_format=output_type,
        **kwargs,
    )
    if tracker is not None:
        tracker.add(response.usage)
    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        category = getattr(details, "category", None) if details else None
        raise LLMError(f"Model declined the request (refusal{f': {category}' if category else ''}).")
    if response.stop_reason == "max_tokens":
        raise LLMError(f"Response truncated at max_tokens={max_tokens}.")
    parsed = response.parsed_output
    if parsed is None:
        raise LLMError("Model response did not contain a parsable structured result.")
    return parsed


def describe_api_error(exc: BaseException) -> str:
    """Short, user-facing description of an API failure (never includes the key)."""
    if isinstance(exc, anthropic.AuthenticationError):
        return "authentication failed (check ANTHROPIC_API_KEY)"
    if isinstance(exc, anthropic.PermissionDeniedError):
        return "permission denied for this API key/model"
    if isinstance(exc, anthropic.NotFoundError):
        return "model or endpoint not found (check --model)"
    if isinstance(exc, anthropic.RateLimitError):
        return "rate limited after retries"
    if isinstance(exc, anthropic.APIStatusError):
        return f"API error {exc.status_code}: {getattr(exc, 'message', exc)}"
    if isinstance(exc, anthropic.APIConnectionError):
        return "network error contacting the Anthropic API"
    return f"{type(exc).__name__}: {exc}"


def is_fatal_api_error(exc: BaseException) -> bool:
    """Errors that will fail identically for every request: abort the run instead of continuing."""
    return isinstance(
        exc, (anthropic.AuthenticationError, anthropic.PermissionDeniedError, anthropic.NotFoundError)
    )
