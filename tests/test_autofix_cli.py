"""Tests for the autofix CLI command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from vulnsift.autofix.prompts import PatchEdit, PatchProposal
from vulnsift.cli import main

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "sample-triage-report.json"


class TestAutofixCLI:
    @patch("vulnsift.autofix.agent.structured_call")
    def test_dry_run(self, mock_call, tmp_path: Path):
        """Dry-run should show diffs but not apply patches."""
        mock_call.return_value = PatchProposal(
            edits=[PatchEdit(old="original = 'code'", new="original = 'fixed'")],
            explanation="Used parameterised query.",
            confidence=8,
        )

        # Create source files that the autofix agent expects
        for rel_path in ["src/db/queries.py", "src/web/search.py", "src/config/settings.py"]:
            f = tmp_path / rel_path
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("original = 'code'\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "autofix",
                "--input", str(FIXTURE),
                "--dry-run",
                "--repo-root", str(tmp_path),
                "--min-risk", "7",
            ],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )

        assert result.exit_code == 0, result.output
        assert "patch" in result.output.lower() or "confidence" in result.output.lower()
        for rel_path in ["src/db/queries.py", "src/web/search.py", "src/config/settings.py"]:
            assert (tmp_path / rel_path).read_text(encoding="utf-8") == "original = 'code'\n"

    def test_no_eligible_findings(self, tmp_path: Path):
        """When min-risk is very high, no findings should match."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "autofix",
                "--input", str(FIXTURE),
                "--dry-run",
                "--repo-root", str(tmp_path),
                "--min-risk", "10",
            ],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )

        assert result.exit_code == 0
        assert "no eligible" in result.output.lower()

    def test_list_only_no_api_key(self) -> None:
        """List-only should not require ANTHROPIC_API_KEY."""
        import os

        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "autofix",
                "--input",
                str(FIXTURE),
                "--list-only",
                "--min-risk",
                "7",
            ],
            env=env,
        )
        assert result.exit_code == 0
        assert "eligible" in result.output.lower()
        assert "finding-1" in result.output or "sql-injection" in result.output
