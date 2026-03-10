# VulnSift

**From noise to signal** — AI-powered vulnerability triage. Turn SAST/SCA scanner output into clear, actionable remediation.

Enterprise security scanners routinely produce hundreds of findings per run, with a large share being false positives or low-priority noise. VulnSift ingests scan output (SARIF, Snyk, Semgrep, Trivy), runs Claude-powered triage to score real-world risk, flags likely false positives, and generates Markdown remediation cards developers can act on.

**For:** Security engineers, AppSec teams, and developers who run SAST/SCA and want to prioritize and remediate without drowning in noise.

## Try it in 30 seconds (no API key needed)

```bash
pip install vulnsift
cd /path/to/VulnSift   # or clone the repo
vulnsift validate --input fixtures/sample.sarif.json
vulnsift triage --input fixtures/sample.sarif.json --dry-run
```

Use `--dry-run` and `validate` anytime to parse and inspect; only `triage` (real AI calls) needs `ANTHROPIC_API_KEY`.

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

## FAQ / Gotchas

- **No API key?** Use `vulnsift validate` or `vulnsift triage --dry-run` to parse and inspect scans without calling the API.
- **Cost / rate limits?** Triage calls Claude per finding. Use `--limit N` to cap the number of findings (e.g. `--limit 20` for a quick run).
- **Unsupported format?** Use `--format sarif|snyk|semgrep|trivy` if auto-detection fails, or open an issue with a sample (redacted).
- **Large scans?** Run with `--limit` first to validate; then run full triage when ready.

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
