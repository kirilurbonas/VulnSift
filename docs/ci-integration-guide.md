# CI Integration Guide

This guide shows how to set up VulnSift as a CI gate in GitHub Actions.

## Option 1: Use the VulnSift GitHub Action (recommended)

The simplest way to integrate VulnSift is with the reusable action. It handles installation, triage, PR comments, and gating in one step.

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

      # Run your scanner (example: Semgrep)
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: auto
          generateSarif: true

      # Triage findings and post PR comment
      - name: VulnSift Triage
        uses: kirilurbonas/VulnSift@main
        with:
          scan-file: semgrep.sarif
          format: sarif
          threshold: "7"
          context: "Python web application"
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### What happens

1. Your scanner runs and produces a findings file (SARIF, Snyk JSON, etc.)
2. VulnSift triages each finding with Claude, scoring risk 0-10
3. A comment is posted (or updated) on the PR with a risk summary
4. The step fails with exit code 2 if any non-FP finding scores >= the threshold

### Action outputs

The action exposes these outputs for use in subsequent steps:

```yaml
- name: Check results
  if: always()
  run: |
    echo "Report: ${{ steps.vulnsift.outputs.report-json }}"
    echo "Max risk: ${{ steps.vulnsift.outputs.max-risk }}"
    echo "Gate: ${{ steps.vulnsift.outputs.gate-result }}"
```

## Option 2: Run VulnSift directly

For more control, install and run VulnSift as a CLI tool:

```yaml
- name: Install VulnSift
  run: pip install vulnsift

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
  if: always() && github.event_name == 'pull_request'
  run: |
    vulnsift github-comment \
      --input vulnsift-output/triage-report.json \
      --threshold 7 \
      --output comment.md
    # Use gh CLI to post the comment
    gh pr comment ${{ github.event.pull_request.number }} --body-file comment.md
  env:
    GH_TOKEN: ${{ github.token }}
```

## Auto-fix in CI

You can also run the auto-fix agent in CI to automatically open fix PRs:

```yaml
- name: Auto-fix high-risk findings
  if: steps.vulnsift.outputs.gate-result == 'failed'
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    GH_TOKEN: ${{ github.token }}
  run: |
    vulnsift autofix \
      --input vulnsift-output/triage-report.json \
      --min-risk 8 \
      --open-pr
```

## Tips

- **Cost control**: Use `--limit N` or `--sample N` to cap the number of findings triaged per run.
- **Privacy**: Use `--redact-code` to avoid sending code snippets to Claude.
- **Large repos**: VulnSift warns when a scan has >1000 findings. Consider using `--sample 50` for initial runs.
- **Multiple scanners**: Run VulnSift once per scanner output, or convert all outputs to SARIF first.
