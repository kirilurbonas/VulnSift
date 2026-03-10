"""CLI tests: validate and triage (mocked) with fixtures."""

from pathlib import Path

from click.testing import CliRunner

from vulnsift.cli import main

runner = CliRunner()


def test_validate_sarif(sample_sarif_path: Path) -> None:
    result = runner.invoke(main, ["validate", "--input", str(sample_sarif_path), "--format", "sarif"])
    assert result.exit_code == 0
    assert "Parsed" in result.output
    assert "finding" in result.output.lower()


def test_validate_auto(sample_sarif_path: Path) -> None:
    result = runner.invoke(main, ["validate", "--input", str(sample_sarif_path), "--format", "auto"])
    assert result.exit_code == 0
    assert "Parsed" in result.output
    assert "sarif" in result.output.lower()


def test_validate_snyk(sample_snyk_path: Path) -> None:
    result = runner.invoke(main, ["validate", "--input", str(sample_snyk_path), "--format", "snyk"])
    assert result.exit_code == 0
    assert "Parsed" in result.output


def test_validate_missing_file() -> None:
    result = runner.invoke(main, ["validate", "--input", "/nonexistent", "--format", "sarif"])
    assert result.exit_code != 0
    assert "Error" in result.output or "failed" in result.output.lower()


def test_triage_without_key(sample_sarif_path: Path) -> None:
    import os
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    result = runner.invoke(
        main,
        ["triage", "--input", str(sample_sarif_path), "--format", "sarif"],
        env=env,
    )
    # Should fail with API key error when first triage call is made
    assert result.exit_code != 0 or "ANTHROPIC_API_KEY" in result.output or "Error" in result.output


def test_report_requires_input() -> None:
    result = runner.invoke(main, ["report"])
    assert result.exit_code != 0


def test_version() -> None:
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_triage_dry_run(sample_sarif_path: Path) -> None:
    result = runner.invoke(
        main,
        ["triage", "--input", str(sample_sarif_path), "--format", "sarif", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Dry run" in result.output
    assert "Would triage" in result.output


def test_triage_gate_threshold_dry_run(sample_sarif_path: Path) -> None:
    # In dry-run mode, gate-threshold should not cause a non-zero exit; no triage is performed.
    result = runner.invoke(
        main,
        [
            "triage",
            "--input",
            str(sample_sarif_path),
            "--format",
            "sarif",
            "--dry-run",
            "--gate-threshold",
            "1",
        ],
    )
    assert result.exit_code == 0


def test_triage_limit(sample_sarif_path: Path) -> None:
    result = runner.invoke(
        main,
        ["triage", "--input", str(sample_sarif_path), "--format", "sarif", "--limit", "1", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Would triage" in result.output


def test_triage_sample_dry_run(sample_sarif_path: Path) -> None:
    result = runner.invoke(
        main,
        ["triage", "--input", str(sample_sarif_path), "--format", "sarif", "--sample", "1", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Would triage" in result.output
