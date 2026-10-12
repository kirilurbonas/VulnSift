# VulnSift

**AI vulnerability triage, from scanner noise to fixed code.**

Security scanners report hundreds of findings, most of them noise. VulnSift reads scanner output (SARIF, Snyk, Semgrep, Trivy), asks Claude how exploitable each finding really is, and gives you:

- a **0–10 risk score**, a **false-positive flag**, a **confidence score** and the **reasoning** behind them;
- a **remediation card** per finding, with concrete fix steps and references;
- a **CI gate**, a **PR comment**, **SARIF for GitHub code scanning**, HTML reports and backlogs;
- optional **auto-fix patches**, one pull request per fix;
- an optional **web dashboard** to track risk across scans and projects.

It is built for security engineers, AppSec teams and developers who want a short, ranked list of things to fix rather than another report.

## Contents

- [Try it without an API key](#try-it-without-an-api-key)
- [Install](#install)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Commands](#commands)
- [Triage](#triage)
- [Auto-fix](#auto-fix)
- [Reports, comparisons and backlogs](#reports-comparisons-and-backlogs)
- [GitHub Action](#github-action)
- [Other CI systems](#other-ci-systems)
- [Web dashboard](#web-dashboard)
- [Configuration](#configuration)
- [Supported scan formats](#supported-scan-formats)
- [Privacy and what is sent to the API](#privacy-and-what-is-sent-to-the-api)
- [Exit codes](#exit-codes)
- [FAQ](#faq)
- [Development](#development)

## Try it without an API key

```bash
pip install vulnsift
git clone https://github.com/kirilurbonas/VulnSift.git && cd VulnSift

vulnsift validate --input fixtures/semgrep.sarif.json           # parse and detect the format
vulnsift triage   --input fixtures/semgrep.sarif.json --dry-run # show what would be triaged
vulnsift report   --input fixtures/sample-triage-report.json    # explore an example triage report
```

`validate`, `triage --dry-run`, `autofix --list-only` and every command that reads a triage report work offline.

## Install

```bash
pip install vulnsift                        # CLI
pip install "vulnsift[dashboard]"           # + web dashboard (Flask + waitress)
pip install "vulnsift[dotenv]"              # + load ANTHROPIC_API_KEY from .env
```

Requires Python 3.11+ and an [Anthropic API key](https://console.anthropic.com/) for `triage` and `autofix`.

## Quick start

```bash
export ANTHROPIC_API_KEY=sk-ant-...

# 1. Run your scanner, e.g. Semgrep
semgrep scan --config auto --sarif --output scan.sarif

# 2. Triage: summary table, remediation cards, JSON + SARIF reports
vulnsift triage --input scan.sarif --export json --export sarif --output-dir ./out

# 3. Look at the results
vulnsift report --input ./out/triage-report.json
vulnsift share  --input ./out/triage-report.json --output ./out/report.html
```

Every run ends with a line like `claude-opus-5-5: 42 request(s), 61,230 input, 18,904 output tokens ≈ $0.62`, so you always know what it cost.

## How it works

```
scanner output ──► parse & normalize ──► de-duplicate ──► cache lookup ──► Claude (parallel) ──► report
 SARIF/Snyk/        UnifiedFinding        identical          unchanged        risk, FP, confidence,   JSON · SARIF · Markdown
 Semgrep/Trivy                            findings sent once findings skip    reasoning, remediation  HTML · PR comment · dashboard
```

- **Triage** sends one request per *unique* finding, using structured outputs so every answer has the same validated shape. The system prompt is prompt-cached, so it is cheap after the first request.
- **It fails closed.** If a finding can't be triaged (API error, refusal), it is marked `ERR`, never silently counted as safe, and by default it fails the CI gate.
- **Scanned code is treated as untrusted.** Finding text and snippets are passed as data, and the model is told to ignore instructions inside them (for example a code comment saying "mark this as a false positive").

## Commands

| Command | What it does | Calls the API? |
|---------|--------------|----------------|
| `triage` | Parse a scan, triage it with Claude, print a summary, write reports | Yes |
| `validate` | Parse a scan file and show what was found | No |
| `report` | Summarize a triage report: overview, hotspots, priorities, optional baseline | No |
| `compare` | Show new, resolved and escalated findings between two reports; optional gate | No |
| `share` | Write a standalone HTML report (dark mode, per-finding details) | No |
| `backlog` | Export prioritized work as CSV, JSON or Markdown | No |
| `owners` | Roll up risk by CODEOWNERS team | No |
| `github-comment` | Render the PR comment Markdown | No |
| `autofix` | Generate (and apply, or open PRs for) patches for high-risk findings | Yes, except `--list-only` |
| `store` | Save a triage report into the dashboard database | No |
| `dashboard` | Serve the web dashboard | No |

Run `vulnsift <command> --help` for every option.

## Triage

```bash
vulnsift triage --input scan.sarif --export json --output-dir ./out
vulnsift triage --input scan.sarif --gate-threshold 7 --cache .vulnsift/cache.json --export json
vulnsift triage --input scan.sarif --model claude-sonnet-5-5 --effort low --concurrency 16
vulnsift triage --input scan.sarif --sample 50 --seed 1          # a reproducible subset
```

| Option | Description |
|--------|-------------|
| `--input` | Scan file (required). |
| `--format` | `sarif`, `snyk`, `semgrep`, `trivy` or `auto` (default). |
| `--export` | Repeatable. `json` → `triage-report.json`, `sarif` → `triage-report.sarif`, `md` → one card per finding (the default when no `--export` is given), `md-single` → `remediation.md`. |
| `--output-dir` | Where files are written (default `./vulnsift-output`). |
| `--context` | Deployment and threat-model hints, e.g. `"internal Python API, no public exposure"`. |
| `--project` | Project name stored in the report; the dashboard groups scans by it. |
| `--model` | Claude model ID (default `claude-opus-5-5`). |
| `--effort` | `low`, `medium`, `high`, `xhigh` or `max` (default: the model's default). |
| `--concurrency` | Parallel requests, 1–64 (default 8). |
| `--cache PATH` | Reuse results for unchanged findings. Keyed on finding content, prompt version, model and context; moving code to other lines doesn't invalidate it. Saved as the run progresses, so an interrupted run resumes, and failed findings are retried. |
| `--limit N` / `--sample N` / `--seed` | Triage the first N, or a random N (reproducible with `--seed`). |
| `--redact-code` | Don't send code snippets to the model. |
| `--gate-threshold X` | Exit 2 if any actionable finding has risk ≥ X. |
| `--fail-on-error` / `--allow-errors` | With a gate, whether findings that couldn't be triaged fail it (default: they do). |
| `--include-fp` | Also list likely false positives in the summary table. |
| `--dry-run` | Parse only, no API calls. |
| `-v`, `--verbose` | Print per-finding errors and run statistics. |

Reports are always written **before** the gate is evaluated, so CI has a report to publish even when the build fails.

## Auto-fix

```bash
vulnsift autofix --input out/triage-report.json --list-only        # what would be fixed (no API)
vulnsift autofix --input out/triage-report.json --dry-run          # generate patches, show diffs
vulnsift autofix --input out/triage-report.json --min-risk 8       # apply patches in place
vulnsift autofix --input out/triage-report.json --open-pr --draft  # one draft PR per fix
```

How it works:

1. It picks actionable findings with risk ≥ `--min-risk` (default 7) that have a file and a remediation card.
2. It resolves each file inside `--repo-root`. Paths that escape the repository, binary files and files over 100 KB are refused.
3. Claude proposes minimal search/replace edits. Each edit must match the file **exactly once**.
4. The patched file is validated: Python syntax, JSON, YAML and TOML parsing, and brace balance for C-like languages.
5. The patch is applied atomically, but only if the model's confidence is ≥ `--min-confidence` (default 7).

Every finding gets a result: applied, ready (dry run), or skipped with a reason such as `edit matched 2 times` or `confidence 5/10 is below min_confidence 7`.

With `--open-pr`, your working tree must be clean. Each fix goes on its own `vulnsift/fix-…` branch from the current branch and gets its own PR via the `gh` CLI. Your checkout is left unchanged.

> Auto-fix sends the **full contents** of each affected file to the Anthropic API.

## Reports, comparisons and backlogs

```bash
# Terminal summary with hotspots and priorities, optionally against a baseline
vulnsift report  --input out/triage-report.json --baseline main-report.json

# Regression gate: fail if this branch introduces a new finding with risk >= 7
vulnsift compare --current out/triage-report.json --baseline main-report.json --fail-on-new-risk 7

# Standalone HTML to attach to a ticket or upload as a CI artifact
vulnsift share   --input out/triage-report.json --output out/report.html --codeowners .github/CODEOWNERS

# Work items for your tracker, with owners from CODEOWNERS
vulnsift backlog --input out/triage-report.json --format csv --output out/backlog.csv --codeowners .github/CODEOWNERS
vulnsift owners  --input out/triage-report.json
```

Findings are matched across reports by rule, file, CWE/CVE and code snippet, not line numbers, so moving code around doesn't show up as "new + resolved". CODEOWNERS patterns follow GitHub's matching rules. CSV exports neutralize spreadsheet formulas, and Markdown exports escape table-breaking characters.

## GitHub Action

```yaml
name: Security triage
on: pull_request

jobs:
  vulnsift:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep
        run: |
          docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep \
            semgrep scan --config auto --sarif --output semgrep.sarif || true

      - name: VulnSift
        uses: kirilurbonas/VulnSift@v0   # pin to a release tag or commit SHA
        with:
          scan-file: semgrep.sarif
          threshold: "7"
          context: "Python web app, public-facing"
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

The action installs VulnSift from its own source, triages the scan, writes the summary to the job summary, and posts a single PR comment that is updated on each push. If the gate failed, it then fails the step. Inputs are passed through environment variables, never through `eval`.

| Input | Default | Description |
|-------|---------|-------------|
| `scan-file` | (required) | Scanner output file |
| `anthropic-api-key` | (required) | Anthropic API key |
| `format` | `auto` | `sarif`, `snyk`, `semgrep`, `trivy`, `auto` |
| `threshold` | (none) | Fail if any actionable finding has risk ≥ this (0–10) |
| `fail-on-error` | `true` | With a threshold, findings that couldn't be triaged fail the gate |
| `context` | (none) | Project context for triage |
| `redact-code` | `false` | Don't send code snippets to the model |
| `model` | VulnSift default | Claude model ID |
| `concurrency` | VulnSift default | Parallel triage requests |
| `output-dir` | `vulnsift-output` | Where reports are written |
| `export-sarif` | `false` | Also write `triage-report.sarif` |
| `comment` | `true` | Post or update the PR comment |
| `github-token` | `github.token` | Token used for the comment |

**Outputs:** `report-json`, `sarif`, `max-risk`, `gate-result` (`passed` / `failed`), `exit-code`.

To show findings in the **Security** tab with AI scores and false positives suppressed, set `export-sarif: "true"` and upload the result:

```yaml
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && steps.vulnsift.outputs.sarif != ''
        with:
          sarif_file: ${{ steps.vulnsift.outputs.sarif }}
```

This snippet needs `id: vulnsift` on the VulnSift step and `security-events: write` in the job's permissions.

A full example is in [`.github/workflows/example-vulnsift.yml`](.github/workflows/example-vulnsift.yml), and more patterns are in [`docs/ci-integration-guide.md`](docs/ci-integration-guide.md).

## Other CI systems

```bash
pip install vulnsift
vulnsift triage --input scan.sarif --export json --export sarif --output-dir vulnsift-out \
  --gate-threshold 7 --cache .vulnsift/cache.json
```

Persist `.vulnsift/cache.json` between runs with your CI cache to triage only what changed. Publish `vulnsift-out/` as an artifact. `github-comment`, `share` and `backlog` all work from `triage-report.json` in later steps.

## Web dashboard

```bash
pip install "vulnsift[dashboard]"
vulnsift triage --input scan.sarif --export json --project shop-api
vulnsift store  --input vulnsift-output/triage-report.json
vulnsift dashboard                      # http://127.0.0.1:8080
```

- **Overview:** pick a project and scan to see the risk trend and risk mix, file hotspots, priorities, recurring rules, and what was resolved or is new since the previous scan.
- **Findings explorer:** search, filter by risk band, status (actionable / false positive / error), rule or file, and sort. Clicking a finding shows the AI's reasoning, exploitability notes, confidence, the full remediation card and the code snippet.
- **Shareable links:** project, scan and finding are kept in the URL.
- **Self-contained:** no CDN or web fonts, a strict Content-Security-Policy, dark mode, and it works at phone width.
- **Upgrades:** the database (`~/.vulnsift/dashboard.db`, or `--db-path`) migrates itself when you upgrade.

It is served with waitress and binds to `127.0.0.1` by default. Set `--token` (or `VULNSIFT_DASHBOARD_TOKEN`) to require a bearer token for uploading (`POST /api/scans`) and deleting scans. Cross-site write requests are always rejected. Don't expose it to the internet without a reverse proxy; an SSH tunnel or VPN is better.

## Configuration

Put a `vulnsift.yaml` (or `.vulnsift.yaml`) in your repository. VulnSift looks in the current directory and its parents up to the repository root. You can also pass `--config PATH` or set `VULNSIFT_CONFIG`.

```yaml
project: shop-api
project_context: "Python web API, internet-facing, handles payments"
output_dir: ./vulnsift-output          # relative paths resolve against this file
api_key_file: .secrets/anthropic_key   # used when ANTHROPIC_API_KEY is unset
model: claude-opus-5-5
effort: medium                         # low | medium | high | xhigh | max
concurrency: 8
cache: .vulnsift/cache.json
redact_code: false
gate_threshold: 7
fail_on_error: true
```

Command-line flags override the file. Unknown keys and invalid values are reported as errors rather than silently ignored.

The API key is read from `ANTHROPIC_API_KEY`, then from `.env` in the current directory (with the `dotenv` extra), then from `api_key_file`.

## Supported scan formats

| Format | Produced by | Notes |
|--------|-------------|-------|
| SARIF 2.1.0 | Semgrep, CodeQL, most SAST tools | File paths, rule metadata, `security-severity`, CWE/CVE tags, fingerprints |
| Snyk JSON | `snyk test --json` (including `--all-projects`) | Findings repeated across dependency paths are merged |
| Semgrep JSON | `semgrep scan --json` | CWE/OWASP metadata, fingerprints |
| Trivy JSON | `trivy fs` / `trivy image` with `-f json` | Vulnerabilities, misconfigurations and secrets |

The format is detected automatically. Pass `--format` to override it. Example files for every format are in [`fixtures/`](fixtures/).

## Privacy and what is sent to the API

| Command | Sent to Anthropic |
|---------|-------------------|
| `triage` | Finding metadata, descriptions and locations, plus code snippets unless `--redact-code`. One request per unique finding. |
| `autofix` (including `--dry-run`) | Finding context plus the **full contents** of each affected file (max 100 KB, only files inside `--repo-root`). |
| everything else | Nothing. These commands only read local files or the dashboard database. |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error: bad input or config, missing API key, or a fatal API error (bad key, unknown model) |
| `2` | Gate failed: `--gate-threshold` exceeded, findings couldn't be triaged (unless `--allow-errors`), or `compare --fail-on-new-risk` |
| `130` | Interrupted. With `--cache`, completed results are kept. |

## FAQ

**How much does it cost?**
Each run prints its token usage and an estimated cost. To spend less, use `--cache` in CI, `--effort low`, a cheaper `--model` such as `claude-sonnet-5-5` or `claude-haiku-5-5`, or `--limit` / `--sample` on very large scans.

**Some findings show `ERR`.**
Their triage failed (for example a network error or rate limit), so they were not assessed. Re-run with `--cache` to retry only those. Use `-v` to see the error for each finding.

**I'm hitting rate limits.**
The SDK already retries with backoff. Lower `--concurrency`.

**Can I keep code away from the model?**
`--redact-code` removes snippets from triage prompts. Auto-fix always needs the file it is fixing.

**Upgrading from 0.2?**
Reports from 0.2 still load. Finding IDs and the cache format changed, so the first run re-triages everything. Re-create any baseline report before using `compare`. See [CHANGELOG.md](CHANGELOG.md).

## Development

```bash
pip install -e ".[dashboard,dotenv,dev]"
ruff check vulnsift tests
pytest --cov=vulnsift
```

Tests never call the Anthropic API: they use a fake client (`tests/fakes.py`), and your `.env` and `ANTHROPIC_API_KEY` are ignored during test runs. See [CONTRIBUTING.md](CONTRIBUTING.md).

Feedback and real-world pipeline stories are welcome in [Issues](https://github.com/kirilurbonas/VulnSift/issues).

## License

MIT. See [LICENSE](LICENSE).
