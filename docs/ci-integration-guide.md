# CI Integration Guide

This guide shows how to set up VulnSift as a CI gate in GitHub Actions.

## Option 1: Use the VulnSift GitHub Action (recommended)

The reusable action installs VulnSift **from the action's own source** (the exact ref you pin), triages your
scanner output, writes a job summary, posts or updates a PR comment, and gates the build.

### Step 1: Add your Anthropic API key as a secret

Go to **Settings > Secrets and variables > Actions** in your repository and add `ANTHROPIC_API_KEY`.

### Step 2: Create a workflow

Create `.github/workflows/vulnsift.yml`:

```yaml
name: VulnSift PR Triage

on:
  pull_request:
    branches: [main]

jobs:
  vulnsift:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      # Run your scanner (example: Semgrep via its official container image).
      # `|| true` keeps the job going when Semgrep reports findings; VulnSift decides pass/fail.
      - name: Run Semgrep
        run: |
          docker run --rm -v "${PWD}:/src" -w /src semgrep/semgrep \
            semgrep scan --config auto --sarif --output semgrep.sarif || true

      # Triage findings, post the PR comment, gate the build.
      # Pin a release tag (e.g. @v0) or a full commit SHA rather than a branch.
      - name: VulnSift Triage
        id: vulnsift
        uses: kirilurbonas/VulnSift@v0
        with:
          scan-file: semgrep.sarif
          format: sarif
          threshold: "7"
          context: "Python web application"
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### What happens

1. Your scanner runs and produces a findings file (SARIF, Snyk JSON, Semgrep JSON, or Trivy JSON).
2. VulnSift triages each finding with Claude, scoring risk 0-10, and writes
   `<output-dir>/triage-report.json` (always, even when the gate fails).
3. The PR comment markdown is added to the job summary, and on `pull_request` / `pull_request_target`
   events a single VulnSift comment is posted or updated on the PR.
4. The action fails with exit code 2 if any actionable (assessed, non-false-positive) finding scores >= the
   threshold. By default, findings whose triage **errored** also fail the gate (set `fail-on-error: "false"`
   to ignore them). Any other error exits with code 1.

All inputs are passed to the CLI as separate arguments via environment variables — they are never
`eval`'d, so values such as `context` cannot inject shell commands.

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-file` | *(required)* | Path to the scanner output file. |
| `anthropic-api-key` | *(required)* | Anthropic API key. |
| `format` | `auto` | `auto`, `sarif`, `snyk`, `semgrep`, or `trivy`. |
| `threshold` | `""` | Gate threshold 0-10. Empty disables the gate. |
| `fail-on-error` | `true` | With a threshold, errored triages fail the gate (`--fail-on-error`); `false` passes `--allow-errors`. |
| `context` | `""` | Project context for risk assessment. |
| `redact-code` | `false` | `true` to avoid sending code snippets to the model. |
| `model` | `""` | Claude model ID (`--model`); empty uses VulnSift's default. |
| `concurrency` | `""` | Findings triaged in parallel (`--concurrency`); empty uses VulnSift's default. |
| `output-dir` | `vulnsift-output` | Where the report (and SARIF / PR comment) are written. |
| `export-sarif` | `false` | `true` also writes `<output-dir>/triage-report.sarif`. |
| `comment` | `true` | Post/update a PR comment (PR events only). |
| `github-token` | `${{ github.token }}` | Token used to post the PR comment. |

### Outputs

| Output | Description |
|--------|-------------|
| `report-json` | Path to `triage-report.json` (empty if triage failed before writing it). |
| `sarif` | Path to `triage-report.sarif` when `export-sarif: "true"`. |
| `max-risk` | Highest risk score among assessed, non-FP findings (errored findings are ignored). |
| `gate-result` | `passed` or `failed` (empty when no threshold is set or triage errored). |
| `exit-code` | Exit code of `vulnsift triage`: `0` ok, `1` error, `2` gate failed. |

```yaml
- name: Check results
  if: always()
  run: |
    echo "Report:   ${{ steps.vulnsift.outputs.report-json }}"
    echo "Max risk: ${{ steps.vulnsift.outputs.max-risk }}"
    echo "Gate:     ${{ steps.vulnsift.outputs.gate-result }}"
```

### Uploading the SARIF to code scanning

The action does not upload SARIF itself. To show VulnSift results in the Security tab, enable
`export-sarif` and upload the file (requires `security-events: write`):

```yaml
- name: VulnSift Triage
  id: vulnsift
  uses: kirilurbonas/VulnSift@v0
  with:
    scan-file: semgrep.sarif
    export-sarif: "true"
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Upload SARIF
  if: always() && steps.vulnsift.outputs.sarif != ''
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.vulnsift.outputs.sarif }}
```

## Option 2: Run VulnSift directly

For more control, install and run VulnSift as a CLI tool:

```yaml
- name: Install VulnSift
  run: pip install vulnsift  # consider pinning a version: vulnsift==X.Y.Z

- name: Triage findings
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    vulnsift triage \
      --input scan-results.sarif \
      --format auto \
      --export json \
      --gate-threshold 7

- name: Post PR comment
  if: always() && github.event_name == 'pull_request' && hashFiles('vulnsift-output/triage-report.json') != ''
  run: |
    vulnsift github-comment \
      --input vulnsift-output/triage-report.json \
      --threshold 7 \
      --output comment.md
    gh pr comment "$PR_NUMBER" --body-file comment.md
  env:
    GH_TOKEN: ${{ github.token }}
    PR_NUMBER: ${{ github.event.pull_request.number }}
```

`vulnsift triage` exit codes: `0` ok, `1` error, `2` gate failed. With `--export json` the report is written
before the gate is evaluated, so later steps can always read it.

## Auto-fix in CI

The auto-fix agent can open one pull request per fix. It asks Claude for minimal search/replace edits,
applies them in memory, validates the result (Python syntax, brace balance, JSON/YAML/TOML parsing), and only
uses patches whose model confidence is at least the minimum (default 7/10). Each fix gets its own branch
(`vulnsift/fix-<finding-id>`) cut from the base branch, containing only that one file; the working tree must
be clean and nothing is left modified on the base branch. File paths from the report are confined to the
repository root (no `..`, absolute paths outside the repo, or symlink escapes).

```yaml
- name: Auto-fix high-risk findings
  if: always() && steps.vulnsift.outputs.gate-result == 'failed'
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    GH_TOKEN: ${{ github.token }}
  run: |
    git config user.name "github-actions[bot]"
    git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
    vulnsift autofix \
      --input vulnsift-output/triage-report.json \
      --min-risk 8 \
      --open-pr
```

The job needs `contents: write` and `pull-requests: write` permissions. Note that the action writes its
output directory into the workspace; make sure it is git-ignored (or use an `output-dir` outside the
checkout) so the working tree is clean before opening fix PRs. On `pull_request` events the checkout is a
detached merge commit, so run auto-fix from a `push`/`workflow_dispatch` workflow on a real branch.
Auto-fix sends full source files of the affected findings to the Anthropic API.

## Tips

- **Cost control**: Use `--limit N` or `--sample N` to cap the number of findings triaged per run.
- **Privacy**: Use `--redact-code` (action input `redact-code: "true"`) to avoid sending code snippets to Claude.
- **Large repos**: VulnSift warns when a scan has >1000 findings. Consider using `--sample 50` for initial runs.
- **Multiple scanners**: Run VulnSift once per scanner output, or convert all outputs to SARIF first.
