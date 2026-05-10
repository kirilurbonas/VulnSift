"""Tests for vulnsift.config."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from vulnsift.config import VulnSiftConfig, resolve_anthropic_api_key


def test_resolve_api_key_from_env() -> None:
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "  sk-test  "}):
        assert resolve_anthropic_api_key(VulnSiftConfig()) == "sk-test"


def test_resolve_api_key_from_file(tmp_path: Path) -> None:
    key_file = tmp_path / "key.txt"
    key_file.write_text("sk-from-file\n", encoding="utf-8")
    cfg = VulnSiftConfig(api_key_file=str(key_file))
    with patch.dict(os.environ, {}, clear=True):
        assert resolve_anthropic_api_key(cfg) == "sk-from-file"


def test_resolve_api_key_env_wins_over_file(tmp_path: Path) -> None:
    key_file = tmp_path / "key.txt"
    key_file.write_text("from-file", encoding="utf-8")
    cfg = VulnSiftConfig(api_key_file=str(key_file))
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "from-env"}):
        assert resolve_anthropic_api_key(cfg) == "from-env"


def test_resolve_api_key_none_when_missing(tmp_path: Path) -> None:
    cfg = VulnSiftConfig(api_key_file=str(tmp_path / "nonexistent"))
    with patch.dict(os.environ, {}, clear=True):
        assert resolve_anthropic_api_key(cfg) is None
