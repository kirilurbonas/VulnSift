"""Pydantic models: UnifiedFinding, TriageResult, RemediationCard."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


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


class TriageReport(BaseModel):
    """Full triage report: all findings with triage and remediation."""

    schema_version: str = "1.0"
    prompt_version: str = "1.0"
    entries: list[TriageReportEntry] = Field(default_factory=list)
    source_file: str = ""
