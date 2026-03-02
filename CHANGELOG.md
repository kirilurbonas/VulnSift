# Changelog

All notable changes to VulnSift are documented here. The project follows [Semantic Versioning](https://semver.org/). Schema version `1.0` is used for triage report JSON export.

## [0.2.0] - Unreleased

### Added

- **Semgrep and Trivy parsers**: Ingest Semgrep `--json` and Trivy `-f json` output; normalized into `UnifiedFinding`.
- **Format auto-detection**: `--format auto` (default for `triage` and `validate`) detects SARIF, Snyk, Semgrep, or Trivy from file content.
- **Config file**: Optional `vulnsift.yaml` or `.vulnsift.yaml` with `project_context`, `output_dir`, `api_key_file`; CLI options override.
- **CLI options**: `--verbose` / `-v`, `--dry-run`, `--limit N`; `--export md-single` for one `remediation.md` file.
- **TriageReport**: `schema_version` field (e.g. `1.0`) for report JSON.
- **Error hints**: Validation and triage errors suggest next steps (e.g. run `vulnsift validate`).
- **Fixtures**: `fixtures/sample.semgrep.json`, `fixtures/sample.trivy.json`.
- **Tests**: Parser tests for Semgrep/Trivy and `detect_format`; CLI tests for `--format auto`, `--dry-run`, `--limit`.
- **Docs**: README updated with all four formats, config example, and "Running VulnSift in CI" section.

### Changed

- Default `--format` for `triage` and `validate` is now `auto` instead of `sarif`.
- Dependency: added `pyyaml` for config file support.

## [0.1.0] - Initial release

- SARIF 2.1.0 and Snyk JSON parsers.
- Claude-powered triage with risk score and false-positive flag.
- Markdown remediation cards and JSON report export.
- Commands: `triage`, `validate`, `report`.
- Rich CLI summary table and fixtures for local testing.
