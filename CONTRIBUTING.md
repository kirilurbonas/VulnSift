# Contributing to VulnSift

## Development setup

1. Clone the repo and create a virtual environment (Python 3.11+).
2. Install the package and dev dependencies:

   ```bash
   pip install -e ".[dashboard,dotenv,dev]"
   ```

3. Copy `.env.example` to `.env` and set `ANTHROPIC_API_KEY` if you want to run triage locally.

## Running tests

```bash
pytest --cov=vulnsift
```

Tests never call the Anthropic API: they use the fake client in `tests/fakes.py`, and an autouse fixture clears `ANTHROPIC_API_KEY` and disables `.env` loading.

## Linting

```bash
ruff check vulnsift tests
```

## Pre-commit (optional)

To run ruff before each commit, install [pre-commit](https://pre-commit.com/) and add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.15.0
    hooks:
      - id: ruff
        args: [--fix]
```

## Submitting changes

Open a pull request against `main`. Ensure CI (lint + tests) passes.
