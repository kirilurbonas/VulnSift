"""Tests for the autofix CLI command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from vulnsift.cli import main

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "sample-triage-report.json"


class TestAutofixCLI:
    @patch("vulnsift.autofix.agent.Anthropic")
    def test_dry_run(self, mock_cls, tmp_path: Path):
        """Dry-run should show diffs but not apply patches."""
        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        # Create mock response
        tool_block = MagicMock()
        tool_block.type = "tool_use"
        tool_block.name = "submit_patch"
        tool_block.input = {
            "patched_code": 'cursor.execute("SELECT * FROM users WHERE id=?", (uid,))\n',
            "explanation": "Used parameterised query.",
            "confidence": 8,
        }
        response = MagicMock()
        response.content = [tool_block]
        mock_client.messages.create.return_value = response

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

        assert result.exit_code == 0
        assert "patch" in result.output.lower() or "confidence" in result.output.lower()

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
                "--min-risk", "11",
            ],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )

        assert result.exit_code == 0
        assert "no eligible" in result.output.lower()
