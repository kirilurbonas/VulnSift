"""Load vulnsift.yaml / .vulnsift.yaml. CLI options override config values."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vulnsift.llm import DEFAULT_MODEL


class ConfigError(ValueError):
    """The config file exists but is invalid."""


class VulnSiftConfig(BaseModel):
    """Project config (vulnsift.yaml). CLI options override these."""

    model_config = ConfigDict(extra="forbid")

    project: str | None = Field(default=None, description="Project name used by the dashboard and reports.")
    project_context: str | None = Field(default=None, description="Project context for triage.")
    output_dir: str = Field(default="./vulnsift-output", description="Default output directory.")
    api_key_file: str | None = Field(default=None, description="Path to file containing ANTHROPIC_API_KEY.")
    redact_code: bool = Field(default=False, description="Do not send code snippets to the AI model.")
    gate_threshold: float | None = Field(
        default=None, ge=0, le=10, description="Exit with code 2 if any non-FP risk >= this."
    )
    fail_on_error: bool = Field(default=True, description="With a gate, findings that failed triage fail it too.")
    model: str = Field(default=DEFAULT_MODEL, description="Claude model ID used for triage and autofix.")
    effort: Literal["low", "medium", "high", "xhigh", "max"] | None = Field(
        default=None, description="Reasoning effort; omit to use the model default."
    )
    concurrency: int = Field(default=8, ge=1, le=64, description="Parallel triage requests.")
    cache: str | None = Field(default=None, description="Triage cache file path.")


CONFIG_FILENAMES = ("vulnsift.yaml", ".vulnsift.yaml", "vulnsift.yml", ".vulnsift.yml")


def find_config(cwd: str | Path | None = None) -> Path | None:
    """Return the nearest config file, searching cwd then parents up to the repository root."""
    start = Path(cwd or ".").resolve()
    for directory in (start, *start.parents):
        for name in CONFIG_FILENAMES:
            p = directory / name
            if p.is_file():
                return p
        if (directory / ".git").exists():
            break
    return None


def load_config(cwd: str | Path | None = None, *, path: str | Path | None = None) -> VulnSiftConfig:
    """Load config from an explicit path or the nearest config file. Returns defaults if none exists.

    Raises ConfigError when a config file exists but is malformed, so mistakes are not silently ignored.
    Relative paths inside the file (output_dir, api_key_file, cache) are resolved against the file's directory.
    """
    cfg_path = Path(path) if path else find_config(cwd)
    if cfg_path is None:
        return VulnSiftConfig()
    if not cfg_path.is_file():
        raise ConfigError(f"Config file not found: {cfg_path}")

    import yaml

    try:
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"{cfg_path}: invalid YAML: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"{cfg_path}: expected a mapping of settings at the top level.")
    try:
        cfg = VulnSiftConfig.model_validate(data)
    except ValidationError as e:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or '(root)'}: {err['msg']}" for err in e.errors()
        )
        raise ConfigError(f"{cfg_path}: {problems}") from e

    base = cfg_path.parent
    for field in ("output_dir", "api_key_file", "cache"):
        if field not in data:
            continue
        value = getattr(cfg, field)
        if value and not Path(value).expanduser().is_absolute():
            setattr(cfg, field, str(base / value))
    return cfg


def resolve_anthropic_api_key(cfg: VulnSiftConfig | None = None) -> str | None:
    """
    Return API key from ANTHROPIC_API_KEY env, or from api_key_file in config if env is unset/empty.
    Never logs the key. Returns None if unavailable.
    """
    env_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if env_key.strip():
        return env_key.strip()
    if cfg and cfg.api_key_file:
        p = Path(cfg.api_key_file).expanduser()
        if not p.is_absolute():
            p = Path.cwd() / p
        try:
            if p.is_file():
                return p.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None
    return None
