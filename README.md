# VulnSift

**AI-powered vulnerability triage and remediation** — from scanner noise to fixed code.

VulnSift ingests SAST/SCA scanner output (SARIF, Snyk, Semgrep, Trivy), uses Claude to score real-world risk, flags false positives, generates remediation cards, and **automatically creates fix PRs** for high-risk findings. Run it as a **GitHub Action** that posts risk summaries on every PR, or explore trends in the built-in **web dashboard**.

**For:** Security engineers, AppSec teams, and developers who want to go from scan results to merged fixes — not just reports.

## Try it in 30 seconds (no API key needed)

```bash
pip install vulnsift
cd /path/to/VulnSift   # or clone the repo
vulnsift validate --input fixtures/sample.sarif.json
vulnsift triage --input fixtures/sample.sarif.json --dry-run
```

Use `--dry-run` and `validate` anytime to parse and inspect; only `triage` (real AI calls) needs `ANTHROPIC_API_KEY`.

## Key features

- **Multi-scanner ingestion**: SARIF 2.1.0, Snyk, Semgrep, and Trivy JSON normalized into a single `UnifiedFinding` model.
- **AI triage with risk scoring**: Claude assesses exploitability and business context, producing a 0–10 risk score and false-positive flag.
- **Auto-fix agent**: Generates code patches for high-risk findings and opens fix PRs automatically.
- **GitHub Action**: First-class CI gate that posts a risk summary comment on every PR.
- **Web dashboard**: Scan history, risk trends, recurring vulnerabilities, and remediation progress.
- **Developer-friendly remediation cards**: Markdown cards with business impact, step-by-step fixes, and code snippets.

## Requirements

- Python 3.11+
- [Anthropic API key](https://console.anthropic.com/) (for AI triage)

## Install

```bash
pip install vulnsift
```

Or from source:

```bash
git clone https://github.com/kirilurbonas/vulnsift.git
cd vulnsift
pip install .
```

## Quick start

For real triage (AI calls), set your API key. Optionally use a `.env` file in the project root — VulnSift auto-loads it if `python-dotenv` is installed (`pip install vulnsift[dotenv]` or `pip install python-dotenv`):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# Or: add ANTHROPIC_API_KEY=sk-ant-... to .env and install vulnsift[dotenv]
```

### Usage overview

```bash
# 1) Sanity-check a scan file (no API calls; format auto-detected)
vulnsift validate --input scan.sarif --format auto

# 2) Triage findings and write remediation cards + JSON report
vulnsift triage --input scan.sarif --format auto --export json --output-dir ./out

# 3) Re-print a summary from a previous JSON report
vulnsift report --input ./out/triage-report.json
```

### Usage: validate

Validate a scan file and see how many findings VulnSift can parse (no API calls):

```bash
vulnsift validate --input scan.sarif --format auto
```

### Usage: triage

Run AI triage over findings, print a risk-ranked summary table, and write remediation cards and an optional JSON or single-Markdown report:

```bash
vulnsift triage --input scan.sarif --format auto --export json --output-dir ./out
vulnsift triage --input scan.sarif --export md-single   # one remediation.md file
```

Use `--dry-run` to parse only (no API calls). Use `--limit N` to triage the first N findings, or `--sample N` to randomly sample N. Use `--redact-code` to avoid sending code snippets to the model. Use `--gate-threshold 7` to exit with code 2 when any non–false-positive finding has risk ≥ 7 (for CI gates). Use `--verbose` for extra logging.

### Usage: report

Summarize a previously exported triage report:

```bash
vulnsift report --input ./out/triage-report.json
```

## Commands

| Command    | Description |
|-----------|-------------|
| `triage`  | Parse a scan file, triage each finding with Claude, print a colour summary table, and write Markdown remediation cards. Use `--export json` to save the full report. |
| `validate`| Parse and validate a scan file (SARIF, Snyk, Semgrep, Trivy; use `--format auto` to detect) without calling the API. |
| `report`  | Print a summary table from a previously exported `triage-report.json`. |
| `autofix` | Generate AI-powered code patches for high-risk findings. Use `--dry-run` to preview diffs, `--open-pr` to create GitHub PRs. |
| `github-comment` | Render a GitHub PR comment from a triage report JSON. Used by the GitHub Action. |
| `store`   | Store a triage report in the dashboard database for trend tracking. |
| `dashboard` | Launch the web dashboard (requires `pip install vulnsift[dashboard]`). |

## Options (triage)

- **`--input`** — Scan file path (SARIF, Snyk, Semgrep, or Trivy JSON).
- **`--format`** — `sarif`, `snyk`, `semgrep`, `trivy`, or `auto` (default: auto-detect from file).
- **`--export`** — `json` (full report), `md` (per-finding cards), or `md-single` (one `remediation.md`).
- **`--output-dir`** — Directory for Markdown/JSON (default: from `vulnsift.yaml` or `./vulnsift-output`).
- **`--context`** — Project context for risk assessment (overrides config).
- **`--include-fp`** — Include likely false positives in the summary table.
- **`--limit N`** — Triage only the first N findings.
- **`--dry-run`** — Parse and validate only; do not call the triage API.
- **`--sample N`** — Randomly sample N findings to triage (good for large scans).
- **`--redact-code`** — Do not send code snippets to the AI model (privacy/safe mode).
- **`--gate-threshold FLOAT`** — Exit with code 2 if any non-FP finding has risk ≥ this (CI gate).
- **`--verbose`** / **`-v`** — Verbose output.

## Config file

Optional `vulnsift.yaml` or `.vulnsift.yaml` in the project root:

```yaml
project_context: "Python app, internal only"
output_dir: ./vulnsift-output
api_key_file: .secrets/anthropic_key
redact_code: false
gate_threshold: 7   # optional: fail CI if any non-FP risk >= 7
```

CLI options override these values.

## Exit codes

- **0** — Success.
- **1** — Error (bad input, missing config, API failure).
- **2** — Gate failed: at least one non–false-positive finding has risk score ≥ `--gate-threshold`.

## Supported scan formats

- **SARIF 2.1.0** — Generic SAST output (many commercial and open-source scanners).
- **Snyk JSON** — Output from `snyk test --json`.
- **Semgrep JSON** — Output from `semgrep scan --json`.
- **Trivy JSON** — Output from `trivy scan -f json` (e.g. `Results[].Vulnerabilities`).

## Sample fixtures

The repo includes minimal sample files under `fixtures/`:

- `fixtures/sample.sarif.json` — SARIF 2.1.0 with one SQL injection finding.
- `fixtures/sample.snyk.json` — Snyk-style JSON with one `lodash` vulnerability.
- `fixtures/sample.semgrep.json` — Semgrep result (e.g. unsafe pickle).
- `fixtures/sample.trivy.json` — Trivy vulnerability result.

Try the CLI without a real scan:

```bash
vulnsift validate --input fixtures/sample.sarif.json --format auto
```

## GitHub Action

VulnSift ships as a reusable GitHub Action. Add it to any PR workflow to automatically triage scanner findings and post a risk summary comment:

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

The action will:
1. Run AI triage on all findings
2. Post/update a PR comment with a risk summary table and recommended actions
3. Fail the step if any non-FP finding scores >= the threshold (CI gate)

See `.github/workflows/example-vulnsift.yml` for a complete example.

### Action inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `scan-file` | Yes | — | Path to scanner output file |
| `format` | No | `auto` | Scanner format (sarif, snyk, semgrep, trivy, auto) |
| `threshold` | No | — | Gate threshold (0-10). Fail if any finding >= this |
| `context` | No | — | Project context for risk assessment |
| `redact-code` | No | `false` | Don't send code snippets to the model |
| `anthropic-api-key` | Yes | — | Anthropic API key |
| `github-token` | No | `github.token` | Token for posting PR comments |
| `comment` | No | `true` | Post/update a PR comment |

## Auto-fix agent

VulnSift can automatically generate code patches for high-risk findings:

```bash
# Preview fixes without modifying files
vulnsift autofix --input triage-report.json --dry-run

# Apply patches and create GitHub PRs
vulnsift autofix --input triage-report.json --open-pr --min-risk 8
```

The auto-fix agent:
1. Reads each high-risk finding from a triage report
2. Loads the affected source file
3. Uses Claude to generate a minimal, safe patch
4. Validates the patch (syntax check for Python, brace balance for JS/TS/etc.)
5. Optionally creates a branch and opens a PR per fix (requires `gh` CLI)

Options: `--dry-run`, `--min-risk N` (default 7), `--repo-root .`, `--open-pr`.

## Web dashboard

Track scan results over time with the built-in dashboard:

```bash
pip install vulnsift[dashboard]

# Store reports after each triage
vulnsift triage --input scan.sarif --export json
vulnsift store --input vulnsift-output/triage-report.json

# Launch dashboard
vulnsift dashboard --port 8080
```

The dashboard shows:
- **Scan history** — all stored scans with findings counts and risk scores
- **Risk trends** — max and average risk score over time
- **Top recurring vulnerabilities** — most frequent rules across scans
- **Severity breakdown** — critical / medium / low / false positive distribution

## Running VulnSift in CI (manual)

For CI setups without the GitHub Action, run VulnSift directly:

```yaml
- name: VulnSift triage
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    vulnsift triage --input scan-results.sarif --format auto --export json --output-dir ./vulnsift-out
```

## FAQ / Gotchas

- **No API key?** Use `vulnsift validate` or `vulnsift triage --dry-run` to parse and inspect scans without calling the API.
- **Cost / rate limits?** Triage calls Claude per finding. Use `--limit N` to cap the number of findings (e.g. `--limit 20` for a quick run).
- **Unsupported format?** Use `--format sarif|snyk|semgrep|trivy` if auto-detection fails, or open an issue with a sample (redacted).
- **Large scans?** Use `--limit N` or `--sample N` to triage a subset; VulnSift will warn when a scan has >1000 findings.

## Development

```bash
pip install . pytest pytest-asyncio ruff
ruff check vulnsift tests
pytest tests/ -v
```

For more details (including contribution guidelines), see `CONTRIBUTING.md`.

**Feedback:** [Open an issue](https://github.com/kirilurbonas/VulnSift/issues) — we’re especially interested in how AppSec and dev teams use VulnSift in real pipelines.

## License

MIT. See [LICENSE](LICENSE).
