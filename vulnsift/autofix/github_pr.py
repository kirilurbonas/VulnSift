"""Git branch and GitHub PR creation via subprocess."""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(RuntimeError):
    """Raised when a git or gh command fails."""


def _run(args: list[str], cwd: Path) -> str:
    """Run a subprocess command, raise GitError on failure."""
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise GitError(f"{' '.join(args)}: {result.stderr.strip()}")
    return result.stdout.strip()


def get_current_branch(repo_root: Path) -> str:
    """Return the current git branch name."""
    return _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root)


def create_fix_branch(repo_root: Path, finding_id: str) -> str:
    """Create and checkout a new branch for the fix. Returns the branch name."""
    safe_id = "".join(c if c.isalnum() or c in "-_" else "-" for c in finding_id)[:40]
    branch = f"vulnsift/fix-{safe_id}"
    _run(["git", "checkout", "-b", branch], cwd=repo_root)
    return branch


def commit_and_push(repo_root: Path, files: list[Path], message: str) -> None:
    """Stage files, commit, and push to origin."""
    for f in files:
        _run(["git", "add", str(f)], cwd=repo_root)
    _run(["git", "commit", "-m", message], cwd=repo_root)
    branch = get_current_branch(repo_root)
    _run(["git", "push", "-u", "origin", branch], cwd=repo_root)


def open_pull_request(
    repo_root: Path,
    title: str,
    body: str,
    base: str,
    head: str,
) -> str:
    """Create a GitHub PR using the gh CLI. Returns the PR URL."""
    output = _run(
        ["gh", "pr", "create", "--title", title, "--body", body, "--base", base, "--head", head],
        cwd=repo_root,
    )
    return output
