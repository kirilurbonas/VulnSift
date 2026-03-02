# VulnSift

**From noise to signal** — AI-powered vulnerability triage. Turn SAST/SCA scanner output into clear, actionable remediation.

Enterprise security scanners routinely produce hundreds of findings per run, with a large share being false positives or low-priority noise. That noise creates alert fatigue: developers stop reading reports, and real vulnerabilities get buried.

VulnSift ingests scan output (SARIF or Snyk JSON), runs Claude-powered triage to score real-world risk, flags likely false positives, and generates Markdown remediation cards developers can actually act on. It is a CLI reference implementation that follows the VulnSift PRD and demonstrates production-grade AI triage patterns.

## Key features

- **Multi-scanner ingestion**: Read SARIF 2.1.0, Snyk, Semgrep, and Trivy JSON and normalize them into a single `UnifiedFinding` model. Use `--format auto` to detect format from file content.
- **AI triage with risk scoring**: Use Claude to assess exploitability and business context, producing a VulnSift Risk Score (0–10) and a likely-false-positive flag.
- **Developer-friendly remediation cards**: Generate Markdown cards with business impact, step-by-step fixes, code snippets, and references.
- **Rich CLI experience**: Colour-coded summary table, optional JSON export for full audit, and fixtures for trying the tool without a real scan.

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

Set your API key (or use `.env` with `ANTHROPIC_API_KEY`):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
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

Use `--dry-run` to parse only (no API calls). Use `--limit N` to triage at most N findings (e.g. for testing). Use `--verbose` for extra logging.

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

## Options (triage)

- **`--input`** — Scan file path (SARIF, Snyk, Semgrep, or Trivy JSON).
- **`--format`** — `sarif`, `snyk`, `semgrep`, `trivy`, or `auto` (default: auto-detect from file).
- **`--export`** — `json` (full report), `md` (per-finding cards), or `md-single` (one `remediation.md`).
- **`--output-dir`** — Directory for Markdown/JSON (default: from `vulnsift.yaml` or `./vulnsift-output`).
- **`--context`** — Project context for risk assessment (overrides config).
- **`--include-fp`** — Include likely false positives in the summary table.
- **`--limit N`** — Triage at most N findings (for testing).
- **`--dry-run`** — Parse and validate only; do not call the triage API.
- **`--verbose`** / **`-v`** — Verbose output.

## Config file

Optional `vulnsift.yaml` or `.vulnsift.yaml` in the project root:

```yaml
project_context: "Python app, internal only"
output_dir: ./vulnsift-output
api_key_file: .secrets/anthropic_key
```

CLI options override these values.

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

## Running VulnSift in CI

Example GitHub Actions job (run after a scanner step that produces a SARIF or JSON file):

```yaml
- name: VulnSift triage
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    vulnsift triage --input scan-results.sarif --format auto --export json --output-dir ./vulnsift-out
```

## Development

```bash
pip install . pytest pytest-asyncio ruff
ruff check vulnsift tests
pytest tests/ -v
```

For more details (including contribution guidelines), see `CONTRIBUTING.md`.

## Architecture / PRD

This implementation follows the VulnSift Product Requirements Document (PRD): a Claude-powered CLI that ingests scanner output (SARIF/Snyk), normalizes findings, runs AI triage with contextual risk scoring, and produces developer-ready remediation guidance. You can browse the source and CI setup at [`https://github.com/kirilurbonas/VulnSift`](https://github.com/kirilurbonas/VulnSift).

## License

MIT. See [LICENSE](LICENSE).
