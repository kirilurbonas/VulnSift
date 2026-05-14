# Changelog

All notable changes to VulnSift are documented here. The project follows [Semantic Versioning](https://semver.org/). Triage report JSON uses `schema_version` and `prompt_version` for compatibility.

## [0.2.0] - Unreleased

### Added

- **Autofix**: `vulnsift autofix` generates patches for high-risk findings; `--dry-run` (still calls API, shows diffs), `--list-only` (no API, lists eligible findings), `--max-fixes N`, `--open-pr` (GitHub PRs via `gh`).
- **GitHub comment**: `vulnsift github-comment` renders a PR comment from a triage report.
- **Dashboard**: `vulnsift store` and `vulnsift dashboard` (optional `pip install vulnsift[dashboard]` / Flask).
- **Baseline compare**: `vulnsift compare` shows new, resolved, and escalating findings between reports; optional `--fail-on-new-risk` exits 2 for regression gating.
- **Shareable HTML artifacts**: `vulnsift share` writes standalone triage or comparison reports for CI artifacts and internal distribution.
- **Backlog export**: `vulnsift backlog` exports prioritized remediation work as CSV, JSON, or Markdown for tickets and planning.
- **CODEOWNERS ownership planning**: `vulnsift owners` summarizes actionable risk by team ownership, while `share` and `backlog` can annotate outputs with owners.
- **GitHub Action**: Reusable workflow for PR triage and comments.
- **Parsers**: Semgrep and Trivy JSON; `--format auto` for triage and validate.
- **Config**: `vulnsift.yaml` / `.vulnsift.yaml` with `project_context`, `output_dir`, `api_key_file`, `redact_code`, `gate_threshold`. **`api_key_file`** is read when `ANTHROPIC_API_KEY` is unset.
- **Triage CLI**: `--verbose`, `--dry-run`, `--limit`, `--sample`, `--seed`, `--redact-code`, `--gate-threshold` (exit 2), `--cache` (JSON triage cache keyed by finding fingerprint + prompt version + redact flag).
- **Triage cache** (`vulnsift/triage/cache.py`): Reuse prior triage results across runs; invalidated when `prompt_version` changes.
- **Exports**: `--export md-single` for one `remediation.md`; `TriageReport.prompt_version` for auditability.
- **Optional extras**: `vulnsift[dotenv]` (auto-load `.env`), `vulnsift[dashboard]` (Flask).
- **CLI**: Top-level `--help` epilog documents exit codes (0 / 1 / 2). `vulnsift --version` uses package `__version__`.
- **Analytics**: shared report analytics for hotspots, immediate priorities, and baseline diffs reused by CLI output, GitHub comments, and the dashboard.

### Changed

- **Version**: 0.2.0 (aligned `pyproject.toml`, `vulnsift.__version__`, and `click.version_option`).
- Default `--format` for `triage` and `validate` is `auto`.
- `vulnsift report` now surfaces hotspots, immediate priorities, and optional `--baseline` comparison output.
- Shared analytics now also power standalone HTML report output and backlog exports so prioritization stays consistent across CLI workflows.
- Ownership-aware planning now understands common CODEOWNERS path prefixes and globs so remediation exports can be assigned directly.
- **Dashboard UI**: redesigned around latest scan pulse, file hotspots, immediate priorities, recurring rules, and trend charts.
- **GitHub comments**: include average actionable risk, riskiest files, and immediate priorities.
- **CI**: Installs `.[dashboard,dotenv]` so dashboard tests run with Flask present.
- **Config loading**: gracefully falls back to defaults if `PyYAML` is unavailable and no config parsing can be done.

### Security / privacy

- **`triage --redact-code`**: Omits scanner code snippets from triage prompts (not a substitute for full data review).
- **`autofix`**: Sends finding metadata and **full source file contents** to the Anthropic API; documented in CLI output and README. Use **`--list-only`** to inspect eligibility without API calls.
- **Dashboard**: Default bind `127.0.0.1`; binding `0.0.0.0` without reverse-proxy auth is not recommended for production.

## [0.1.0] - Initial release

- SARIF 2.1.0 and Snyk JSON parsers.
- Claude-powered triage with risk score and false-positive flag.
- Markdown remediation cards and JSON report export.
- Commands: `triage`, `validate`, `report`.
- Rich CLI summary table and fixtures for local testing.
