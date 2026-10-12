"""Concurrent triage of many findings: de-duplication, caching, error isolation, usage tracking."""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import FIRST_EXCEPTION, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anthropic

from vulnsift.llm import DEFAULT_MODEL, UsageTracker, describe_api_error, is_fatal_api_error
from vulnsift.models import TriageReportEntry, TriageResult, UnifiedFinding
from vulnsift.triage import cache as triage_cache
from vulnsift.triage.agent import triage_finding
from vulnsift.triage.prompts import PROMPT_VERSION

DEFAULT_CONCURRENCY = 8
CACHE_SAVE_EVERY = 10


class FatalTriageError(RuntimeError):
    """An error that would fail identically for every finding (bad key, unknown model)."""


@dataclass
class TriageOptions:
    model: str = DEFAULT_MODEL
    effort: str | None = None
    project_context: str | None = None
    redact_code: bool = False
    concurrency: int = DEFAULT_CONCURRENCY


@dataclass
class TriageStats:
    total: int = 0
    unique: int = 0
    cache_hits: int = 0
    duplicates: int = 0
    api_calls: int = 0
    errors: int = 0


ProgressCallback = Callable[[TriageReportEntry, str], None]
"""Called once per input finding with its entry and a status: 'cached', 'duplicate', 'triaged' or 'error'."""


def run_triage(
    findings: list[UnifiedFinding],
    *,
    client: anthropic.Anthropic,
    options: TriageOptions,
    tracker: UsageTracker | None = None,
    cache_path: Path | None = None,
    on_result: ProgressCallback | None = None,
) -> tuple[list[TriageReportEntry], TriageStats]:
    """Triage findings concurrently and return entries in input order.

    - Findings with identical content (same fingerprint) are sent to the model once.
    - A failed finding becomes an entry with `triage.error` set; it is never silently counted as safe.
    - Authentication / model-not-found errors abort the run with FatalTriageError.
    - The cache (if given) is saved incrementally and on exit, including on failure or Ctrl-C.
    """
    stats = TriageStats(total=len(findings))
    entries: list[TriageReportEntry | None] = [None] * len(findings)
    cache_map: dict[str, dict[str, Any]] = (
        triage_cache.load_cache(cache_path, PROMPT_VERSION) if cache_path else {}
    )
    lock = threading.Lock()
    dirty = 0

    def emit(idx: int, entry: TriageReportEntry, status: str) -> None:
        entries[idx] = entry
        if on_result is not None:
            on_result(entry, status)

    # Group input positions by fingerprint so duplicates share one API call.
    groups: dict[str, list[int]] = {}
    for idx, f in enumerate(findings):
        fp = triage_cache.fingerprint(
            f, PROMPT_VERSION, options.redact_code, model=options.model, project_context=options.project_context
        )
        groups.setdefault(fp, []).append(idx)
    stats.unique = len(groups)

    pending: dict[str, list[int]] = {}
    for fp, idxs in groups.items():
        cached = cache_map.get(fp)
        if cached is not None:
            first = triage_cache.cache_entry_to_report_entry(findings[idxs[0]], cached)
            if first is not None:
                for idx in idxs:
                    emit(idx, first.model_copy(update={"finding": findings[idx]}, deep=True), "cached")
                stats.cache_hits += len(idxs)
                continue
        pending[fp] = idxs

    def save_cache() -> None:
        if cache_path is not None:
            with lock:
                snapshot = dict(cache_map)
            triage_cache.save_cache(cache_path, snapshot, PROMPT_VERSION)

    def work(fp: str, idxs: list[int]) -> None:
        nonlocal dirty
        lead = findings[idxs[0]]
        try:
            result, card = triage_finding(
                lead,
                options.project_context,
                client=client,
                model=options.model,
                effort=options.effort,
                redact_code=options.redact_code,
                tracker=tracker,
            )
        except Exception as exc:  # noqa: BLE001 - isolate per-finding failures
            if is_fatal_api_error(exc):
                raise FatalTriageError(describe_api_error(exc)) from exc
            error = TriageResult(risk_score=0, is_likely_false_positive=False, error=describe_api_error(exc))
            with lock:
                stats.errors += len(idxs)
                stats.api_calls += 1
                for idx in idxs:
                    emit(idx, TriageReportEntry(finding=findings[idx], triage=error.model_copy()), "error")
            return

        base = TriageReportEntry(finding=lead, triage=result, remediation=card)
        with lock:
            stats.api_calls += 1
            stats.duplicates += len(idxs) - 1
            cache_map[fp] = triage_cache.report_entry_to_cache_dict(base)
            dirty += 1
            should_save = dirty % CACHE_SAVE_EVERY == 0
            for n, idx in enumerate(idxs):
                entry = base if n == 0 else base.model_copy(update={"finding": findings[idx]}, deep=True)
                emit(idx, entry, "triaged" if n == 0 else "duplicate")
        if should_save:
            save_cache()

    workers = max(1, min(options.concurrency, len(pending) or 1))
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vulnsift-triage")
    futures: list[Future[None]] = []
    try:
        futures = [executor.submit(work, fp, idxs) for fp, idxs in pending.items()]
        done, _ = wait(futures, return_when=FIRST_EXCEPTION)
        for fut in done:
            exc = fut.exception()
            if exc is not None:
                raise exc
    finally:
        for fut in futures:
            fut.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        save_cache()

    return [e for e in entries if e is not None], stats
