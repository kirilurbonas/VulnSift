"""Git branch and GitHub PR creation (git + gh CLI via subprocess).

`open_fix_prs` creates one independent branch and pull request per patch, each branched from the
base branch, and never leaves modified files behind on the base branch.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

from vulnsift.autofix.patches import PatchError, detect_newline, resolve_repo_path, write_atomic
from vulnsift.models import AutofixResult

MAX_DIFF_IN_BODY = 60_000
BRANCH_PREFIX = "vulnsift/fix-"


class GitError(RuntimeError):
    """Raised when a git or gh command fails (or the repository is not in a usable state)."""


def _run(args: list[str], cwd: Path, *, input: str | None = None) -> str:
    """Run a subprocess command, raise GitError on failure. Returns stripped stdout."""
    try:
        result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, input=input)
    except FileNotFoundError as e:
        raise GitError(f"{args[0]}: command not found") from e
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise GitError(f"{' '.join(args[:3])} failed: {detail}")
    return result.stdout.strip()


def _git(repo_root: Path, *args: str) -> str:
    return _run(["git", *args], cwd=repo_root)


def get_current_branch(repo_root: Path) -> str:
    """Return the current git branch name ('HEAD' when detached)."""
    return _git(repo_root, "rev-parse", "--abbrev-ref", "HEAD")


def ensure_clean_worktree(repo_root: Path) -> None:
    """Raise GitError if the working tree has uncommitted changes or untracked files."""
    status = _git(repo_root, "status", "--porcelain")
    if status:
        raise GitError(
            "working tree is not clean; commit or stash your changes before opening fix PRs "
            "(and run autofix with dry_run=True so patches are not written to the base branch):\n" + status
        )


def safe_branch_id(finding_id: str) -> str:
    """Branch-name-safe version of a finding id (max 40 chars)."""
    safe = re.sub(r"[^A-Za-z0-9_-]+", "-", finding_id).strip("-")[:40].strip("-")
    return safe or "finding"


def _branch_exists(repo_root: Path, branch: str) -> bool:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def _unique_branch_name(repo_root: Path, finding_id: str, salt: str) -> str:
    base = f"{BRANCH_PREFIX}{safe_branch_id(finding_id)}"
    if not _branch_exists(repo_root, base):
        return base
    digest = hashlib.sha256(salt.encode("utf-8")).hexdigest()
    for i in range(0, len(digest) - 6, 6):
        candidate = f"{base}-{digest[i : i + 6]}"
        if not _branch_exists(repo_root, candidate):
            return candidate
    raise GitError(f"could not find a free branch name for {base}")


def create_fix_branch(repo_root: Path, finding_id: str, *, start_point: str | None = None) -> str:
    """Create and check out a new fix branch (from `start_point` if given). Returns the branch name."""
    branch = _unique_branch_name(repo_root, finding_id, start_point or finding_id)
    _git(repo_root, "checkout", "-b", branch, *([start_point] if start_point else []))
    return branch


def commit_and_push(repo_root: Path, files: list[Path], message: str, *, remote: str = "origin") -> None:
    """Stage files, commit, and push the current branch to `remote`."""
    for f in files:
        _git(repo_root, "add", "--", str(f))
    _git(repo_root, "commit", "-m", message)
    branch = get_current_branch(repo_root)
    _git(repo_root, "push", "-u", remote, branch)


def open_pull_request(
    repo_root: Path,
    title: str,
    body: str,
    base: str,
    head: str,
    *,
    draft: bool = False,
) -> str:
    """Create a GitHub PR using the gh CLI (body passed on stdin). Returns the PR URL."""
    args = ["gh", "pr", "create", "--title", title, "--body-file", "-", "--base", base, "--head", head]
    if draft:
        args.append("--draft")
    output = _run(args, cwd=repo_root, input=body)
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return lines[-1] if lines else output


def _fence_for(text: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def build_pr_body(result: AutofixResult, *, max_diff: int = MAX_DIFF_IN_BODY) -> str:
    """Markdown body for a fix PR: finding, file, confidence, explanation and the diff."""
    diff = result.diff
    truncated = len(diff) > max_diff
    if truncated:
        diff = diff[:max_diff].rsplit("\n", 1)[0] + "\n"
    fence = _fence_for(diff)
    parts = [
        "## Automated security fix by VulnSift",
        "",
        f"**Finding:** `{result.finding_id}`",
        f"**File:** `{result.file_path}`",
        f"**Model confidence:** {result.confidence}/10",
        "",
        "### Explanation",
        "",
        result.explanation or "_No explanation provided._",
        "",
        "### Diff",
        "",
        f"{fence}diff",
        diff.rstrip("\n"),
        fence,
    ]
    if truncated:
        parts.extend(["", f"_Diff truncated to {max_diff // 1000} KB; see the Files tab for the full change._"])
    parts.extend(
        [
            "",
            "> This patch was generated by an AI model. Review it carefully and make sure tests pass before merging.",
            "",
            "---",
            "*Generated by [VulnSift](https://github.com/kirilurbonas/VulnSift)*",
        ]
    )
    return "\n".join(parts)


def _has_valid_patch(result: AutofixResult) -> bool:
    return result.skipped_reason is None and bool(result.diff) and bool(result.patched_snippet)


def _one_line(text: str, limit: int) -> str:
    line = " ".join(text.split())
    return line if len(line) <= limit else line[: limit - 3].rstrip() + "..."


def _open_one_pr(
    root: Path, result: AutofixResult, *, base: str, remote: str, draft: bool
) -> str:
    target = resolve_repo_path(root, result.file_path)
    current = target.read_bytes().decode("utf-8")
    if current.replace("\r\n", "\n") != result.original_snippet.replace("\r\n", "\n"):
        raise PatchError(f"{result.file_path} on {base} differs from the content the patch was generated for")

    branch = _unique_branch_name(root, result.finding_id, result.diff)
    _git(root, "checkout", "-b", branch, base)
    committed = False
    try:
        write_atomic(target, result.patched_snippet, newline=detect_newline(current))
        _git(root, "add", "--", str(target))
        subject = _one_line(f"fix(security): remediate {result.finding_id} in {result.file_path}", 72)
        body = _one_line(result.explanation, 2000) if result.explanation else ""
        _git(root, "commit", "-m", subject, *(["-m", body] if body else []))
        committed = True
        _git(root, "push", "-u", remote, branch)
        title = _one_line(f"fix(security): remediate {result.finding_id} in {result.file_path}", 200)
        return open_pull_request(root, title, build_pr_body(result), base, branch, draft=draft)
    finally:
        # Discard anything left in the working tree (it was clean when we started) and go back to base.
        _git(root, "checkout", "-f", base)
        if not committed:
            _git(root, "branch", "-D", branch)


def open_fix_prs(
    repo_root: Path | str,
    results: list[AutofixResult],
    *,
    base_branch: str | None = None,
    remote: str = "origin",
    draft: bool = False,
) -> list[tuple[AutofixResult, str | None, str | None]]:
    """Open one pull request per valid patch, each on its own branch cut from `base_branch`.

    Requires a clean working tree (raises GitError otherwise), so run autofix_report with dry_run=True
    first. `base_branch` defaults to the current branch (raises GitError on a detached HEAD). Results
    without a valid patch (skipped_reason set, or empty diff) are ignored. For each patch: create branch
    `vulnsift/fix-<id>` (with a short suffix if it exists locally), write the patched file, commit that one
    file, push to `remote`, and `gh pr create` (optionally --draft). The original checkout is restored
    afterwards and no modified files are left on the base branch.

    Returns (result, pr_url, error) per attempted patch: pr_url is set on success, error otherwise.
    """
    root = Path(repo_root).resolve()
    original = get_current_branch(root)
    if original == "HEAD":
        original = _git(root, "rev-parse", "HEAD")
        if base_branch is None:
            raise GitError("HEAD is detached; pass base_branch explicitly")
    base = base_branch or original
    ensure_clean_worktree(root)

    outcomes: list[tuple[AutofixResult, str | None, str | None]] = []
    try:
        for result in results:
            if not _has_valid_patch(result):
                continue
            try:
                _git(root, "checkout", base)
                url = _open_one_pr(root, result, base=base, remote=remote, draft=draft)
                outcomes.append((result, url, None))
            except (GitError, PatchError, OSError, UnicodeDecodeError) as e:
                outcomes.append((result, None, str(e)))
    finally:
        _git(root, "checkout", "-f", original)
    return outcomes
