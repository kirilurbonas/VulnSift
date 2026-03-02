# VulnSift

**From noise to signal** — AI-powered vulnerability triage. Turn SAST/SCA scanner output into clear, actionable remediation.

Enterprise security scanners routinely produce hundreds of findings per run, with a large share being false positives or low-priority noise. That noise creates alert fatigue: developers stop reading reports, and real vulnerabilities get buried.

VulnSift ingests scan output (SARIF or Snyk JSON), runs Claude-powered triage to score real-world risk, flags likely false positives, and generates Markdown remediation cards developers can actually act on. It is a CLI reference implementation that follows the VulnSift PRD and demonstrates production-grade AI triage patterns.

## Key features

- **Multi-scanner ingestion**: Read SARIF 2.1.0 and Snyk JSON scan results and normalize them into a single `UnifiedFinding` model.
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
# 1) Sanity-check a scan file (no API calls)
vulnsift validate --input scan.sarif --format sarif

# 2) Triage findings and write remediation cards + JSON report
vulnsift triage --input scan.sarif --format sarif --export json --output-dir ./out

# 3) Re-print a summary from a previous JSON report
vulnsift report --input ./out/triage-report.json
```

### Usage: validate

Validate a scan file and see how many findings VulnSift can parse (no calls to the Claude API):

```bash
vulnsift validate --input scan.sarif --format sarif
```

### Usage: triage

Run AI triage over findings, print a risk-ranked summary table, and write remediation cards and an optional JSON report:

```bash
vulnsift triage --input scan.sarif --format sarif --export json --output-dir ./out
```

### Usage: report

Summarize a previously exported triage report:

```bash
vulnsift report --input ./out/triage-report.json
```

## Commands

| Command    | Description |
|-----------|-------------|
| `triage`  | Parse a scan file, triage each finding with Claude, print a colour summary table, and write Markdown remediation cards. Use `--export json` to save the full report. |
| `validate`| Parse and validate a scan file (SARIF or Snyk JSON) without calling the API. |
| `report`  | Print a summary table from a previously exported `triage-report.json`. |

## Options (triage)

- **`--input`** — Scan file path (SARIF or Snyk JSON).
- **`--format`** — `sarif` or `snyk`.
- **`--export json`** — Write full triage report (all findings, including false positives) to JSON in the output dir.
- **`--output-dir`** — Directory for Markdown cards and optional JSON (default: `./vulnsift-output`).
- **`--context`** — Optional project context for risk assessment (e.g. `"Python app, internal only"`).
- **`--include-fp`** — Include likely false positives in the summary table (they always appear in the full JSON export).

## Supported scan formats

- **SARIF 2.1.0** — Generic SAST output (e.g. many commercial and open-source scanners).
- **Snyk JSON** — Output from `snyk test --json`.

## Sample fixtures

The repo includes minimal sample files under `fixtures/`:

- `fixtures/sample.sarif.json` — SARIF 2.1.0 file with a single SQL injection finding in `src/app.py`; useful for demoing `validate` and `triage`.
- `fixtures/sample.snyk.json` — Snyk-style JSON with one `lodash` vulnerability; useful for checking the Snyk parser and CLI behaviour.

Use them to try the CLI without a real scan:

```bash
vulnsift validate --input fixtures/sample.sarif.json --format sarif
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
