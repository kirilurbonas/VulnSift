# Contributing to VulnSift

Thanks for helping. This guide covers local setup, the checks every change must pass, and how releases are made.

## Setup

```bash
git clone https://github.com/kirilurbonas/VulnSift.git && cd VulnSift
python -m venv .venv && . .venv/bin/activate      # Python 3.11+
pip install -e ".[dashboard,dotenv,dev]"
pre-commit install                                  # run lint/type checks on every commit
```

Copy `.env.example` to `.env` and set `ANTHROPIC_API_KEY` only if you want to run real triage locally. Never commit `.env`, API keys or scan output from private projects.

## Checks

Every pull request must pass the same checks CI runs:

```bash
ruff check vulnsift tests     # lint
mypy                          # type check (config in pyproject.toml)
pytest --cov                  # tests; fails below 85% coverage
pip-audit --skip-editable     # known vulnerabilities in dependencies
```

Tests never call the Anthropic API. Use the fake client in `tests/fakes.py` (`FakeClient`, `triage_output`, `api_error`). An autouse fixture clears `ANTHROPIC_API_KEY` and disables `.env` loading.

## Making changes

1. Create a branch from `main` (`fix/…`, `feat/…`, `docs/…`).
2. Add or update tests with the change. Bug fixes should include a test that fails without the fix.
3. Update `CHANGELOG.md` under *Unreleased* for anything users will notice, and the README or docs if options or behaviour change.
4. Bump `PROMPT_VERSION` in `vulnsift/triage/prompts.py` when you change the triage prompt or output schema (this invalidates caches). Bump `schema_version` in `vulnsift/models.py` when the report format changes.
5. Open a pull request against `main` and fill in the template. CI (lint, types, tests on Linux/macOS/Windows and Python 3.11–3.14, dependency audit and review, CodeQL, build) must be green, and a code owner must approve.

Use clear, imperative commit messages (`Fix SARIF parsing of artifactLocation.uri`). Conventional prefixes (`fix:`, `feat:`, `docs:`, `ci:`, `deps:`) are welcome.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not as issues or pull requests.

Changes to `action.yml`, `.github/` or dependencies get extra review. Pin new GitHub Actions to a full commit SHA with a version comment, give workflows the least permissions they need, and prefer dependencies that have been released for at least a week.

## Releasing (maintainers)

1. Update the version in `pyproject.toml` and `vulnsift/__init__.py`, and move *Unreleased* in `CHANGELOG.md` to the new version.
2. Merge to `main` and wait for CI.
3. Tag and push: `git tag -s v0.3.0 -m v0.3.0 && git push origin v0.3.0`.
4. The release workflow tests, builds, attests build provenance, publishes to PyPI via trusted publishing (the `pypi` environment), and creates the GitHub release.
5. Move the major tag used by the Action: `git tag -f v0 v0.3.0 && git push -f origin v0`.

## Code of conduct

This project follows the [code of conduct](CODE_OF_CONDUCT.md).
