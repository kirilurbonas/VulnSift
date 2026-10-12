# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes |
| < 0.3   | No. Please upgrade. |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report them privately through [GitHub security advisories](https://github.com/kirilurbonas/VulnSift/security/advisories/new). Include:

- the affected version and command (or GitHub Action input);
- steps to reproduce, ideally with a minimal scan file or triage report;
- the impact you expect (for example code execution, file writes outside the repository, secret exposure).

You can expect an acknowledgement within 3 business days and an initial assessment within 7. Fixes are released as a patch version and credited in the advisory unless you prefer otherwise.

## Scope

In scope:

- the `vulnsift` Python package and CLI;
- the GitHub Action defined in `action.yml`;
- the web dashboard (`vulnsift dashboard`).

Especially relevant: anything that lets untrusted scanner output or scanned source code execute commands, write files outside `--repo-root`, inject into PR comments or the dashboard, leak the Anthropic API key, or make a CI gate pass when it should fail.

Out of scope: the quality of AI risk scores on their own, and vulnerabilities in third-party scanners whose output VulnSift reads.

## How VulnSift handles your data

- Triage sends finding metadata and, unless `--redact-code` is set, code snippets to the Anthropic API. `autofix` sends whole source files. See the [privacy section of the README](README.md#privacy-and-what-is-sent-to-the-api).
- The API key is read from the environment, `.env` or `api_key_file`. It is never written to reports, caches or logs.
- The dashboard binds to `127.0.0.1` by default. Use `--token` before exposing it to anyone else.
