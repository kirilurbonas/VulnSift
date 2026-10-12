## What and why

<!-- What does this change do, and what problem does it solve? Link issues with "Fixes #123". -->

## How it was tested

<!-- Commands you ran, new tests, manual checks. -->

## Checklist

- [ ] Tests added or updated, and `pytest --cov` passes
- [ ] `ruff check vulnsift tests` and `mypy` pass
- [ ] `CHANGELOG.md` updated under *Unreleased* (user-facing changes only)
- [ ] README / docs updated if behaviour or options changed
- [ ] No secrets, API keys or real scan data from private projects in the diff
- [ ] Changes to prompts bump `PROMPT_VERSION`; changes to the report format bump `schema_version`
