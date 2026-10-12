"""Pydantic models: UnifiedFinding, TriageResult, RemediationCard."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, Field

# Risk bands used by every output surface (CLI, HTML, PR comment, dashboard).
HIGH_RISK_THRESHOLD = 7
MEDIUM_RISK_THRESHOLD = 4


def risk_band(score: float) -> str:
    """Return 'high', 'medium' or 'low' for a 0-10 risk score."""
    if score >= HIGH_RISK_THRESHOLD:
        return "high"
    if score >= MEDIUM_RISK_THRESHOLD:
        return "medium"
    return "low"


class Location(BaseModel):
    """Source location for a finding."""

    file_path: str = ""
    start_line: int | None = None
    end_line: int | None = None
    snippet: str | None = None
    region: str | None = None


class UnifiedFinding(BaseModel):
    """Normalized finding from any scanner (SARIF, Snyk, etc.)."""

    id: str = ""
    rule_id: str = ""
    title: str = ""
    message: str = ""
    severity: str = ""  # raw from scanner: critical, high, medium, low, etc.
    description: str = ""
    cve: str | None = None
    cwe: str | None = None
    location: Location = Field(default_factory=Location)
    raw: dict[str, Any] = Field(default_factory=dict)
    source_format: str = ""  # "sarif" | "snyk" | "semgrep" | "trivy"


class TriageResult(BaseModel):
    """AI triage output for a single finding."""

    risk_score: int = Field(ge=0, le=10, description="VulnSift Risk Score 0-10")
    is_likely_false_positive: bool = False
    reasoning: str = ""
    exploitability_notes: str = ""
    confidence: int | None = Field(default=None, ge=0, le=10, description="Model confidence in this assessment.")
    error: str | None = Field(default=None, description="Set when triage failed; the finding was NOT assessed.")

    @property
    def is_error(self) -> bool:
        return self.error is not None


class RemediationCard(BaseModel):
    """Developer-friendly remediation card (plain English)."""

    title: str = ""
    business_impact: str = ""
    steps: list[str] = Field(default_factory=list)
    code_snippet: str | None = None
    reference_links: list[str] = Field(default_factory=list)


class TriageReportEntry(BaseModel):
    """One finding plus its triage result and optional remediation card."""

    finding: UnifiedFinding
    triage: TriageResult
    remediation: RemediationCard | None = None

    @property
    def is_actionable(self) -> bool:
        """Assessed, and not a likely false positive. Errored entries are never actionable (or FP)."""
        return not self.triage.is_error and not self.triage.is_likely_false_positive

    @property
    def is_false_positive(self) -> bool:
        return not self.triage.is_error and self.triage.is_likely_false_positive


class UsageSummary(BaseModel):
    """Token usage and estimated cost for a triage run."""

    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0
    estimated_cost_usd: float | None = None


class TriageReport(BaseModel):
    """Full triage report: all findings with triage and remediation."""

    schema_version: str = "1.1"
    prompt_version: str = "1.0"
    entries: list[TriageReportEntry] = Field(default_factory=list)
    source_file: str = ""
    model: str = ""
    generated_at: str = ""
    project: str | None = None
    usage: UsageSummary | None = None

    @property
    def errored_entries(self) -> list[TriageReportEntry]:
        return [e for e in self.entries if e.triage.is_error]


def max_actionable_risk(entries: Iterable[TriageReportEntry]) -> int:
    """Highest risk score among actionable (assessed, non-FP) entries; 0 if none."""
    return max((e.triage.risk_score for e in entries if e.is_actionable), default=0)


class AutofixResult(BaseModel):
    """Result of an auto-fix attempt for a single finding."""

    finding_id: str = ""
    file_path: str = ""
    original_snippet: str = ""
    patched_snippet: str = ""
    explanation: str = ""
    confidence: int = Field(default=0, ge=0, le=10)
    applied: bool = False
    skipped_reason: str | None = None
    diff: str = ""
