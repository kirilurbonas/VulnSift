# Changelog

All notable changes to VulnSift are documented here. The project follows [Semantic Versioning](https://semver.org/). Triage report JSON uses `schema_version` and `prompt_version` for compatibility.

## [0.3.0] - Unreleased

### Fixed

- **Triage failures no longer pass as false positives.** A finding whose API call failed used to be recorded as `risk_score=0, is_likely_false_positive=True`, so a CI gate could pass on an unassessed scan. Failures are now recorded in `triage.error`, shown as `ERR`, and fail the gate by default (`--allow-errors` to opt out).
- **Gate no longer loses the report.** `triage` writes JSON/SARIF/Markdown *before* exiting with code 2, so the GitHub Action can still post its PR comment when the gate fails.
- **SARIF file paths.** `physicalLocation.artifactLocation.uri` (used by Semgrep, CodeQL and most tools) was ignored, leaving `file_path` empty. Rule lookup via `ruleIndex`/extensions, `security-severity`, CWE/CVE tags and fingerprints are now read too.
- **Snyk** uses `displayTargetFile` for the location, accepts multi-project (`--all-projects`) output, and merges findings repeated across dependency paths. **Trivy** keeps references and fixed versions, and parses misconfigurations and secrets.
- **Autofix safety.** Patches can no longer overwrite whole dependency files with a fragment, paths outside `--repo-root` are refused, one failing finding no longer aborts the run, low-confidence patches are not applied (`--min-confidence`, default 7), and writes are atomic.
- **`--open-pr`** opens one clean PR per fix from the base branch (previously each branch stacked on the previous fix and carried uncommitted changes); a dirty tree is refused.
- **CODEOWNERS** matching follows GitHub's rules (`.github/` paths, unanchored directory names, `*` vs `**`).
- **`compare`** no longer treats findings as new + resolved just because code moved to different lines.
- **Triage cache** is keyed on model and project context as well, saved incrementally and atomically, and never caches errors.
- **Config errors** (invalid YAML, unknown keys, wrong types) are reported instead of silently falling back to defaults.
- **Dashboard** no longer shares one SQLite connection across server threads.
- Rich markup in scanner text is no longer interpreted in the terminal; Markdown/HTML in PR comments and CSV formula prefixes in backlog/owner exports are escaped.

### Added

- Parallel triage (`--concurrency`, default 8), de-duplication of identical findings, prompt caching of the system prompt, a progress bar with ETA, and token/cost reporting (`report.usage`).
- `--model`, `--effort`, `--project`, repeatable `--export` with a new `sarif` format (GitHub code scanning compatible), global `--config` / `VULNSIFT_CONFIG`.
- Triage results now include the model's `confidence`; reports record `model`, `generated_at`, `project` and `usage`. The AI's reasoning and exploitability notes now appear in remediation cards, the HTML report and the PR comment.
- Config keys: `project`, `model`, `effort`, `concurrency`, `cache`, `fail_on_error`. Config is found in parent directories up to the repo root.
- HTML report: per-finding details and dark mode.
- Dashboard: projects, scan selector, a searchable/filterable findings explorer with a detail panel (reasoning, remediation, snippet), "resolved / new since previous scan" progress, dark mode, no external assets, strict CSP, optional bearer token for writes, waitress server, automatic schema migration.
- `vulnsift store --project`, `vulnsift dashboard --token`.
- Autofix: `--min-confidence`, `--model`, `--draft`; a skip reason for every finding that was not patched.

### Changed

- Uses the Anthropic Python SDK 1.x with structured outputs; the default model is `claude-opus-5-5`.
- `PROMPT_VERSION` 2.0 (hardened against prompt injection from scanned code); report `schema_version` 1.1.
- GitHub Action installs VulnSift from the action itself, passes inputs via environment variables (no `eval`), paginates comment lookup, and adds `model`, `concurrency`, `output-dir`, `export-sarif` and `fail-on-error` inputs.
- Packaging moved to PEP 621 metadata; `dev` extra; CI tests Python 3.11–3.13 and macOS with coverage; releases use PyPI trusted publishing after tests pass.

## [0.2.0]


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
