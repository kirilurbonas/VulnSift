# VulnSift

**From noise to signal** — AI-powered vulnerability triage. Turn SAST/SCA scanner output into clear, actionable remediation.

VulnSift ingests SARIF or Snyk JSON, runs Claude-powered triage to score real risk and flag false positives, and outputs a colour-coded summary plus Markdown remediation cards developers can act on.

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

Validate a scan file (no API calls):

```bash
vulnsift validate --input scan.sarif --format sarif
```

Triage findings and get remediation cards:

```bash
vulnsift triage --input scan.sarif --format sarif --export json --output-dir ./out
```

View a previously exported report:

```bash
vulnsift report --input ./out/triage-report.json
```

## Commands

| Command    | Description |
|-----------|-------------|
| `triage`  | Parse scan file, triage each finding with Claude, print summary table and write Markdown remediation cards. Use `--export json` to save full report. |
| `validate`| Parse and validate a scan file (SARIF or Snyk JSON) without calling the API. |
| `report`  | Print summary table from a previously exported triage-report.json. |

## Options (triage)

- `--input` — Scan file path (SARIF or Snyk JSON).
- `--format` — `sarif` or `snyk`.
- `--export json` — Write full triage report (all findings, including false positives) to JSON in the output dir.
- `--output-dir` — Directory for Markdown cards and optional JSON (default: `./vulnsift-output`).
- `--context` — Optional project context for risk assessment (e.g. `"Python app, internal only"`).
- `--include-fp` — Include likely false positives in the summary table (they always appear in the full JSON export).

## Sample fixtures

The repo includes minimal sample files under `fixtures/`:

- `fixtures/sample.sarif.json` — SARIF 2.1.0 with one result.
- `fixtures/sample.snyk.json` — Snyk-style JSON with one vulnerability.

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

## Releasing to PyPI

1. Create a PyPI account and add a token (or use [trusted publishing](https://docs.pypi.org/trusted-publishers/)).
2. In GitHub, add secret `PYPI_API_TOKEN` and (optional) environment `pypi` for the release workflow.
3. Tag a version: `git tag v0.1.0 && git push origin v0.1.0`. The [Release workflow](.github/workflows/release.yml) will build and publish to PyPI.

## License

MIT. See [LICENSE](LICENSE).
