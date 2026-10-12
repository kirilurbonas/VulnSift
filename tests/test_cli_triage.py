"""End-to-end `vulnsift triage` runs against a fake Anthropic client."""

import json
from pathlib import Path

import anthropic
import pytest
from click.testing import CliRunner

from tests.fakes import FakeClient, api_error, triage_output
from vulnsift.cli import main
from vulnsift.models import TriageReport

runner = CliRunner()


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeClient:
    client = FakeClient()
    monkeypatch.setattr("vulnsift.llm.make_client", lambda *a, **k: client)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    return client


def _run(*args: str):
    return runner.invoke(main, list(args), catch_exceptions=False)


def test_triage_writes_json_sarif_and_cards(fake: FakeClient, sample_sarif_path: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = _run(
        "triage", "--input", str(sample_sarif_path), "--output-dir", str(out),
        "--export", "json", "--export", "sarif", "--export", "md", "--project", "shop",
    )
    assert result.exit_code == 0, result.output
    report = TriageReport.model_validate_json((out / "triage-report.json").read_text())
    assert report.entries
    assert report.project == "shop"
    assert report.model == "claude-opus-5-5"
    assert report.usage is not None and report.usage.requests == len(fake.calls)
    sarif = json.loads((out / "triage-report.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(report.entries)
    assert list(out.glob("remediation_*.md"))


def test_gate_failure_still_writes_report(fake: FakeClient, sample_sarif_path: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = _run(
        "triage", "--input", str(sample_sarif_path), "--output-dir", str(out),
        "--export", "json", "--gate-threshold", "7",
    )
    assert result.exit_code == 2
    assert "Gate failed" in result.output
    assert (out / "triage-report.json").is_file()


def test_gate_passes_below_threshold(monkeypatch: pytest.MonkeyPatch, sample_sarif_path: Path, tmp_path: Path) -> None:
    client = FakeClient(lambda kw: triage_output(risk_score=3))
    monkeypatch.setattr("vulnsift.llm.make_client", lambda *a, **k: client)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    result = _run("triage", "--input", str(sample_sarif_path), "--output-dir", str(tmp_path), "--gate-threshold", "7")
    assert result.exit_code == 0, result.output
    assert "Gate passed" in result.output


def test_triage_errors_fail_gate_closed(
    monkeypatch: pytest.MonkeyPatch, sample_sarif_path: Path, tmp_path: Path
) -> None:
    client = FakeClient(lambda kw: api_error(anthropic.InternalServerError, 500, "boom"))
    monkeypatch.setattr("vulnsift.llm.make_client", lambda *a, **k: client)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    result = _run(
        "triage", "--input", str(sample_sarif_path), "--output-dir", str(tmp_path),
        "--export", "json", "--gate-threshold", "7",
    )
    assert result.exit_code == 2
    assert "could not be triaged" in result.output
    report = TriageReport.model_validate_json((tmp_path / "triage-report.json").read_text())
    assert all(e.triage.is_error and not e.triage.is_likely_false_positive for e in report.entries)

    allowed = _run(
        "triage", "--input", str(sample_sarif_path), "--output-dir", str(tmp_path),
        "--gate-threshold", "7", "--allow-errors",
    )
    assert allowed.exit_code == 0, allowed.output


def test_auth_error_exits_1(monkeypatch: pytest.MonkeyPatch, sample_sarif_path: Path, tmp_path: Path) -> None:
    client = FakeClient(lambda kw: api_error(anthropic.AuthenticationError, 401))
    monkeypatch.setattr("vulnsift.llm.make_client", lambda *a, **k: client)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "bad")
    result = runner.invoke(main, ["triage", "--input", str(sample_sarif_path), "--output-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert not (tmp_path / "triage-report.json").exists()


def test_model_and_config_file(fake: FakeClient, sample_sarif_path: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "vulnsift.yaml"
    cfg.write_text("model: claude-sonnet-5-5\nconcurrency: 2\noutput_dir: out\neffort: low\n")
    result = _run("--config", str(cfg), "triage", "--input", str(sample_sarif_path), "--export", "json")
    assert result.exit_code == 0, result.output
    assert {c["model"] for c in fake.calls} == {"claude-sonnet-5-5"}
    assert fake.calls[0]["output_config"] == {"effort": "low"}
    assert (tmp_path / "out" / "triage-report.json").is_file()

    overridden = _run(
        "--config", str(cfg), "triage", "--input", str(sample_sarif_path), "--model", "claude-haiku-5-5",
        "--output-dir", str(tmp_path / "o2"),
    )
    assert overridden.exit_code == 0
    assert fake.calls[-1]["model"] == "claude-haiku-5-5"


def test_invalid_config_is_reported(sample_sarif_path: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "vulnsift.yaml"
    cfg.write_text("gate_threshold: high\nunknown_key: 1\n")
    result = runner.invoke(main, ["--config", str(cfg), "triage", "--input", str(sample_sarif_path), "--dry-run"])
    assert result.exit_code == 1
    assert "gate_threshold" in result.output
    assert "unknown_key" in result.output


def test_markup_in_findings_is_not_interpreted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "t", "rules": []}},
            "results": [{
                "ruleId": "[bold red]rule[/]",
                "message": {"text": "[link=http://evil]x[/link]"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}],
            }],
        }],
    }
    scan = tmp_path / "scan.sarif"
    scan.write_text(json.dumps(sarif))
    client = FakeClient()
    monkeypatch.setattr("vulnsift.llm.make_client", lambda *a, **k: client)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    result = _run("triage", "--input", str(scan), "--output-dir", str(tmp_path / "o"))
    assert result.exit_code == 0
    assert "[bold red]rule" in result.output
