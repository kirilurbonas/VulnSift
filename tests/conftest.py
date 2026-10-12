"""Pytest fixtures and config."""

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def sample_sarif_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "sample.sarif.json"


@pytest.fixture
def sample_snyk_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "sample.snyk.json"


@pytest.fixture
def sample_semgrep_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "sample.semgrep.json"


@pytest.fixture
def sample_trivy_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "sample.trivy.json"


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never read a developer's .env or real API key during tests."""
    monkeypatch.setenv("VULNSIFT_DISABLE_DOTENV", "1")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("VULNSIFT_CONFIG", raising=False)
    monkeypatch.delenv("VULNSIFT_DASHBOARD_TOKEN", raising=False)
