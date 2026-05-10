# VulnSift

**AI-powered vulnerability triage and remediation** — from scanner noise to fixed code.

VulnSift ingests SAST/SCA scanner output (SARIF, Snyk, Semgrep, Trivy), uses Claude to score real-world risk, flags false positives, generates remediation cards, and can **generate fix patches** (and open PRs) for high-risk findings. Run it as a **GitHub Action** that posts risk summaries on PRs, compare reports to spot regressions, or explore trends in the optional **web dashboard**.

**For:** Security engineers, AppSec teams, and developers who want to go from scan results to actionable fixes — not only reports.

## Contents

- [Try it in 30 seconds](#try-it-in-30-seconds-no-api-key-needed)
- [Key features](#key-features)
- [Requirements](#requirements)
- [Privacy and data sent to the API](#privacy-and-data-sent-to-the-api)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Triage options](#options-triage)
- [Autofix options](#autofix-options)
- [Config file](#config-file)
- [Exit codes](#exit-codes)
- [Supported scan formats](#supported-scan-formats)
- [GitHub Action](#github-action)
- [Web dashboard](#web-dashboard)
- [CI examples](#running-vulnsift-in-ci-manual)
- [FAQ](#faq--gotchas)
- [Development](#development)

## Try it in 30 seconds (no API key needed)

```bash
pip install vulnsift
cd /path/to/VulnSift   # or clone the repo
vulnsift validate --input fixtures/sample.sarif.json
vulnsift triage --input fixtures/sample.sarif.json --dry-run
```

Use `validate` and `triage --dry-run` to parse and inspect without the API. Real triage and autofix (except `--list-only`) need an Anthropic API key (env, `.env`, or `api_key_file` in config — see [Config file](#config-file)).

## Key features

- **Multi-scanner ingestion**: SARIF 2.1.0, Snyk, Semgrep, and Trivy JSON normalized into a single `UnifiedFinding` model; `--format auto` detects the format.
- **AI triage**: 0–10 risk score, false-positive flag, Markdown remediation cards, optional JSON export (`schema_version` / `prompt_version` on reports).
- **Cost controls**: `--limit`, `--sample` + `--seed`, optional **`--cache`** JSON to reuse triage for unchanged findings when `prompt_version` matches.
- **CI gates**: `--gate-threshold` (exit code 2) or the same via `vulnsift.yaml`.
- **Baseline compare**: `vulnsift compare` and `vulnsift report --baseline ...` show new, resolved, and escalating findings between scans.
- **Shareable artifacts**: `vulnsift share` writes a standalone HTML report you can upload as a CI artifact or circulate internally.
- **Prioritized backlog**: `vulnsift backlog` exports remediation work as CSV, JSON, or Markdown for tickets and planning.
- **Auto-fix**: Patches for high-risk findings; `--dry-run`, `--list-only`, `--max-fixes`, optional `--open-pr` (requires `gh`).
- **GitHub Action**: PR comment with risk summary and optional gate.
- **Web dashboard** (optional extra): Store reports and view latest scan health, hotspots, priorities, and trends (`vulnsift[dashboard]`).
- **`github-comment`**: Render a PR-ready Markdown comment from `triage-report.json`.

## Requirements

- Python 3.11+
- [Anthropic API key](https://console.anthropic.com/) for commands that call the API (`triage`, `autofix` except `--list-only`)

## Privacy and data sent to the API

| Command | Calls Anthropic? | What is sent (summary) |
|---------|------------------|-------------------------|
| `validate` | No | Local file only. |
| `triage` | Yes (per finding) | Finding metadata, descriptions, locations; code snippets unless `--redact-code`. |
| `triage --dry-run` | No | Local parse only. |
| `autofix` | Yes (per eligible file) | Finding context plus **full contents** of each affected source file (up to an internal size cap). |
| `autofix --dry-run` | Yes | Same as `autofix`; only file writes / PRs are skipped. |
| `autofix --list-only` | No | Reads triage JSON only; prints eligible paths. |
| `github-comment`, `store`, `report`, `compare`, `share`, `backlog` | No | Local JSON / DB only. |

Run `vulnsift --help` for **exit codes** (0 = success, 1 = error, 2 = triage gate failed).

## Install

```bash
pip install vulnsift
```

Optional extras:

```bash
pip install "vulnsift[dotenv]"    # auto-load .env for ANTHROPIC_API_KEY
pip install "vulnsift[dashboard]" # Flask web dashboard
pip install "vulnsift[dotenv,dashboard]"
```

From source:

```bash
git clone https://github.com/kirilurbonas/vulnsift.git
cd vulnsift
pip install .
```

## Quick start

Set your API key, or put it in `.env` (with `vulnsift[dotenv]`), or point `api_key_file` in `vulnsift.yaml` at a small file whose **trimmed contents** are the key (typically one line):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

### Usage overview

```bash
# 1) Sanity-check a scan file (no API calls; format auto-detected)
vulnsift validate --input scan.sarif --format auto

# 2) Triage and write remediation + JSON report
vulnsift triage --input scan.sarif --format auto --export json --output-dir ./out

# 3) Re-print summary from exported JSON, with hotspots and priorities
vulnsift report --input ./out/triage-report.json

# 4) Compare against a baseline report to spot regressions and wins
vulnsift compare --current ./out/triage-report.json --baseline ./out/previous-triage-report.json

# 5) Export a standalone HTML artifact or remediation backlog
vulnsift share --input ./out/triage-report.json --output ./out/triage-report.html
vulnsift backlog --input ./out/triage-report.json --format csv --output ./out/backlog.csv

# 6) Optional: CI-friendly gate + cache (reuse triage when inputs unchanged)
vulnsift triage --input scan.sarif --export json --gate-threshold 7 --cache .vulnsift/triage-cache.json
```

### Usage: validate

```bash
vulnsift validate --input scan.sarif --format auto
```

### Usage: triage

```bash
vulnsift triage --input scan.sarif --format auto --export json --output-dir ./out
vulnsift triage --input scan.sarif --export md-single   # single remediation.md
```

Use `--dry-run` for parse-only. Use `--limit N` / `--sample N` (with optional `--seed`) for subsets. Use `--redact-code` to omit snippets from prompts. Use `--gate-threshold` for CI gates (exit 2). Use `--verbose` for more logging.

### Usage: report

```bash
vulnsift report --input ./out/triage-report.json
vulnsift report --input ./out/triage-report.json --baseline ./out/previous-triage-report.json
```

### Usage: compare

```bash
vulnsift compare --current ./out/triage-report.json --baseline ./out/previous-triage-report.json
vulnsift compare --current ./out/triage-report.json --baseline ./out/main-branch.json --fail-on-new-risk 7
```

### Usage: share

```bash
vulnsift share --input ./out/triage-report.json --output ./out/triage-report.html
vulnsift share --input ./out/triage-report.json --baseline ./out/main-branch.json --output ./out/comparison.html
```

### Usage: backlog

```bash
vulnsift backlog --input ./out/triage-report.json --format csv --output ./out/backlog.csv
vulnsift backlog --input ./out/triage-report.json --format md --top 15
```

## Commands

| Command | Description |
|---------|-------------|
| `triage` | Parse a scan, triage with Claude, Rich summary, Markdown cards. `--export json` saves full report. |
| `validate` | Parse a scan (SARIF, Snyk, Semgrep, Trivy; `--format auto`) without the API. |
| `report` | Print summary from `triage-report.json`, including hotspots and immediate priorities. |
| `compare` | Compare two triage reports to show new, resolved, and escalating findings; optional regression gate. |
| `share` | Write a standalone HTML artifact from a triage report, with optional baseline comparison. |
| `backlog` | Export prioritized remediation work as CSV, JSON, or Markdown. |
| `autofix` | Generate patches from a triage JSON. `--list-only` lists eligible items without API calls. |
| `github-comment` | Render PR comment Markdown from a triage report (used by the GitHub Action). |
| `store` | Append a triage report into the dashboard SQLite DB. |
| `dashboard` | Serve the web UI (`pip install vulnsift[dashboard]`). |

## Options (triage)

- **`--input`** — Scan file (SARIF, Snyk, Semgrep, or Trivy JSON).
- **`--format`** — `sarif`, `snyk`, `semgrep`, `trivy`, or `auto` (default).
- **`--export`** — `json`, `md` (per-finding cards), or `md-single` (one `remediation.md`).
- **`--output-dir`** — Output directory (default: `vulnsift.yaml` or `./vulnsift-output`).
- **`--context`** — Project context for risk (overrides config).
- **`--include-fp`** — Include likely false positives in the summary table.
- **`--limit N`** — Triage only the first N findings (after sampling, if any).
- **`--sample N`** — Randomly sample N findings before `--limit`.
- **`--seed INT`** — RNG seed for `--sample` (reproducible CI).
- **`--cache PATH`** — JSON cache to skip API for unchanged findings (invalidated when `prompt_version` changes).
- **`--dry-run`** — Parse only; no API.
- **`--redact-code`** — Do not send scanner code snippets in triage prompts.
- **`--gate-threshold FLOAT`** — Exit 2 if any non-FP finding has risk ≥ threshold.
- **`--verbose`** / **`-v`** — Verbose output.

## Autofix options

- **`--input`** — `triage-report.json` from `vulnsift triage --export json`.
- **`--repo-root`** — Repository root (default `.`).
- **`--min-risk`** — Minimum risk score to consider (default `7`).
- **`--max-fixes N`** — Cap how many findings are sent to the model.
- **`--dry-run`** — Call API, print diffs; do not write files or open PRs.
- **`--list-only`** — Print eligible findings; **no API**, no key required.
- **`--open-pr`** — After applying patches, create branches/PRs (needs `gh` CLI and git remote).
- **`--verbose`** / **`-v`**

## Config file

Optional `vulnsift.yaml` or `.vulnsift.yaml` in the project root:

```yaml
project_context: "Python app, internal only"
output_dir: ./vulnsift-output
api_key_file: .secrets/anthropic_key   # if ANTHROPIC_API_KEY is unset: read file, strip whitespace
redact_code: false
gate_threshold: 7   # optional: same as triage --gate-threshold
```

CLI flags override YAML.

## Exit codes

- **0** — Success.
- **1** — Error (bad input, missing key/config, API failure).
- **2** — Gate failed: any non–false-positive finding has risk ≥ `--gate-threshold` (triage only).

## Supported scan formats

- **SARIF 2.1.0** — Many SAST tools and GitHub Code Scanning.
- **Snyk JSON** — `snyk test --json`.
- **Semgrep JSON** — `semgrep scan --json`.
- **Trivy JSON** — `trivy scan -f json` (`Results[].Vulnerabilities`).

## Sample fixtures

Under `fixtures/`: `sample.sarif.json`, `sample.snyk.json`, `sample.semgrep.json`, `sample.trivy.json`, and `sample-triage-report.json` (for `report` / `autofix` / `github-comment` demos).

```bash
vulnsift validate --input fixtures/sample.sarif.json --format auto
```

## GitHub Action

Reusable action for PR workflows:

```yaml
- name: VulnSift Triage
  uses: kirilurbonas/VulnSift@main
  with:
    scan-file: semgrep.sarif
    format: sarif
    threshold: "7"
    context: "Python web app, public-facing"
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    comment: "true"
```

The action triages findings, optionally posts/updates a PR comment, and fails the step if any non-FP finding is ≥ `threshold`.

See `.github/workflows/example-vulnsift.yml` for a full workflow.

### Action inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `scan-file` | Yes | — | Path to scanner output |
| `format` | No | `auto` | `sarif`, `snyk`, `semgrep`, `trivy`, `auto` |
| `threshold` | No | — | Gate: fail if any finding ≥ this (0–10) |
| `context` | No | — | Project context for triage |
| `redact-code` | No | `false` | Omit code snippets from triage prompts |
| `anthropic-api-key` | Yes | — | Anthropic API key |
| `github-token` | No | `github.token` | Token for PR comments |
| `comment` | No | `true` | Post/update PR comment |

## Auto-fix agent

**Autofix sends full source files to the Anthropic API** (see privacy table above).

```bash
vulnsift autofix --input triage-report.json --list-only
vulnsift autofix --input triage-report.json --dry-run --repo-root .
vulnsift autofix --input triage-report.json --max-fixes 3 --dry-run --repo-root .
vulnsift autofix --input triage-report.json --open-pr --min-risk 8
```

Flow: load triage JSON → filter by risk / FP / remediation → read source files → Claude proposes patches → validate → apply (unless dry-run) → optional PRs via `gh`.

## Web dashboard

```bash
pip install "vulnsift[dashboard]"
vulnsift triage --input scan.sarif --export json
vulnsift store --input vulnsift-output/triage-report.json
vulnsift dashboard --port 8080
```

The dashboard highlights the latest scan pulse, file hotspots, immediate priorities, recurring rules, and risk trends so teams can decide what to fix first without leaving the browser.

Default bind is **127.0.0.1**. Do not bind **0.0.0.0** on the public internet without auth and a reverse proxy; prefer SSH tunnel or VPN for remote access.

## Running VulnSift in CI (manual)

```yaml
- name: VulnSift triage
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    vulnsift triage --input scan-results.sarif --format auto \
      --export json --output-dir ./vulnsift-out \
      --gate-threshold 7 --cache .vulnsift/triage-cache.json
```

Upload `vulnsift-out/triage-report.json` as a workflow artifact if you need `report`, `github-comment`, or `autofix` in later steps.

To guard against regressions in a later step, compare the artifact against a baseline report:

```bash
vulnsift compare --current vulnsift-out/triage-report.json \
  --baseline baseline-triage-report.json \
  --fail-on-new-risk 7
```

To make the results easy to circulate, also emit an HTML report and backlog artifact:

```bash
vulnsift share --input vulnsift-out/triage-report.json --output vulnsift-out/triage-report.html
vulnsift backlog --input vulnsift-out/triage-report.json --format csv --output vulnsift-out/backlog.csv
```

## FAQ / Gotchas

- **No API key?** Use `validate`, `triage --dry-run`, or `autofix --list-only`. For triage/autofix API runs, set `ANTHROPIC_API_KEY`, use `.env` with `[dotenv]`, or `api_key_file` in YAML.
- **Cost / rate limits?** Triage is one API call per finding; autofix is per eligible file. Use `--limit`, `--sample`, `--cache` (triage), or `--max-fixes` (autofix).
- **Unsupported format?** Pass `--format sarif|snyk|semgrep|trivy` if auto-detect fails.
- **Large scans?** Subset with `--limit` / `--sample`; a warning appears when there are more than 1000 findings.

## Development

```bash
pip install ".[dashboard,dotenv]" pytest pytest-asyncio ruff
ruff check vulnsift tests
pytest tests/ -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines and [CHANGELOG.md](CHANGELOG.md) for release notes.

**Feedback:** [Issues](https://github.com/kirilurbonas/VulnSift/issues) — we welcome real-world pipeline stories.

## License

MIT. See [LICENSE](LICENSE).
