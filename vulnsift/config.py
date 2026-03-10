"""Load and merge vulnsift.yaml / .vulnsift.yaml with CLI options."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


class VulnSiftConfig(BaseModel):
    """Project config (vulnsift.yaml). CLI options override these."""

    project_context: str | None = Field(default=None, description="Project context for triage.")
    output_dir: str = Field(default="./vulnsift-output", description="Default output directory.")
    api_key_file: str | None = Field(default=None, description="Path to file containing ANTHROPIC_API_KEY.")
    redact_code: bool = Field(default=False, description="Do not send code snippets to the AI model.")
    gate_threshold: float | None = Field(default=None, description="Exit with code 2 if any non-FP risk >= this.")


CONFIG_FILENAMES = ("vulnsift.yaml", ".vulnsift.yaml")


def find_config(cwd: str | Path | None = None) -> Path | None:
    """Return path to first existing config file in cwd, or None."""
    cwd = Path(cwd or ".").resolve()
    for name in CONFIG_FILENAMES:
        p = cwd / name
        if p.is_file():
            return p
    return None


def load_config(cwd: str | Path | None = None) -> VulnSiftConfig:
    """Load config from cwd. Returns defaults if no file found."""
    import yaml
    path = find_config(cwd)
    if not path:
        return VulnSiftConfig()

    raw = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(raw) or {}
    except Exception:
        return VulnSiftConfig()
    if not isinstance(data, dict):
        return VulnSiftConfig()
    return VulnSiftConfig(
        project_context=data.get("project_context"),
        output_dir=data.get("output_dir", "./vulnsift-output"),
        api_key_file=data.get("api_key_file"),
        redact_code=bool(data.get("redact_code", False)),
        gate_threshold=data.get("gate_threshold"),
    )
