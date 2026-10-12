"""Tests for the fix-PR orchestration, using a real temporary git repo and a mocked gh CLI."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from vulnsift.autofix import github_pr
from vulnsift.autofix.github_pr import GitError, build_pr_body, open_fix_prs, safe_branch_id
from vulnsift.autofix.patches import generate_diff
from vulnsift.models import AutofixResult

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

APP = "def get(uid):\n    return run('SELECT * FROM t WHERE id=' + uid)\n"
APP_FIXED = "def get(uid):\n    return run('SELECT * FROM t WHERE id=?', (uid,))\n"
CFG = "DEBUG = True\n"
CFG_FIXED = "DEBUG = False\n"


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    empty = tmp_path / "gitconfig"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "--bare", "-q", str(origin)], check=True)
    work = tmp_path / "work"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    git(work, "config", "user.name", "Test")
    git(work, "config", "user.email", "test@example.com")
    (work / "src").mkdir()
    (work / "src" / "app.py").write_text(APP, encoding="utf-8")
    (work / "settings.py").write_text(CFG, encoding="utf-8")
    git(work, "add", ".")
    git(work, "commit", "-q", "-m", "init")
    git(work, "remote", "add", "origin", str(origin))
    git(work, "push", "-q", "-u", "origin", "main")
    return work


@pytest.fixture
def gh_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """Intercept only `gh` invocations; git runs for real."""
    calls: list[dict] = []
    real_run = github_pr._run

    def fake_run(args, cwd, *, input=None):
        if args[0] == "gh":
            calls.append({"args": list(args), "body": input, "branch": git(cwd, "rev-parse", "--abbrev-ref", "HEAD")})
            head = args[args.index("--head") + 1]
            return f"Creating pull request...\nhttps://github.com/acme/app/pull/{len(calls)}?head={head}"
        return real_run(args, cwd, input=input)

    monkeypatch.setattr(github_pr, "_run", fake_run)
    return calls


def _result(fid: str, path: str, old: str, new: str, **kw) -> AutofixResult:
    return AutofixResult(
        finding_id=fid,
        file_path=path,
        original_snippet=old,
        patched_snippet=new,
        diff=generate_diff(path, old, new),
        explanation=kw.pop("explanation", "Fixed it."),
        confidence=kw.pop("confidence", 9),
        **kw,
    )


def _files_on(repo: Path, branch: str) -> list[str]:
    return git(repo, "diff", "--name-only", f"main...{branch}").splitlines()


class TestOpenFixPrs:
    def test_independent_branches(self, repo: Path, gh_calls: list[dict]):
        results = [
            _result("finding/1", "src/app.py", APP, APP_FIXED),
            _result("finding-2", "settings.py", CFG, CFG_FIXED),
            _result("skipped", "settings.py", CFG, CFG_FIXED, skipped_reason="low confidence"),
        ]
        outcomes = open_fix_prs(repo, results)

        assert [(r.finding_id, err) for r, _, err in outcomes] == [("finding/1", None), ("finding-2", None)]
        assert all(url and url.startswith("https://github.com/acme/app/pull/") for _, url, _ in outcomes)

        # Each branch contains exactly its own fix, branched from main.
        assert _files_on(repo, "vulnsift/fix-finding-1") == ["src/app.py"]
        assert _files_on(repo, "vulnsift/fix-finding-2") == ["settings.py"]
        assert git(repo, "show", "vulnsift/fix-finding-1:src/app.py") + "\n" == APP_FIXED
        assert git(repo, "show", "vulnsift/fix-finding-2:src/app.py") + "\n" == APP

        # Pushed to origin.
        remote_branches = git(repo, "ls-remote", "--heads", "origin")
        assert "refs/heads/vulnsift/fix-finding-1" in remote_branches
        assert "refs/heads/vulnsift/fix-finding-2" in remote_branches

        # Back on main with a clean tree and unchanged files.
        assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
        assert git(repo, "status", "--porcelain") == ""
        assert (repo / "src" / "app.py").read_text(encoding="utf-8") == APP

        first = gh_calls[0]
        assert first["args"][first["args"].index("--base") + 1] == "main"
        assert "--draft" not in first["args"]
        assert "```diff" in first["body"]
        assert "finding/1" in first["body"]
        assert "9/10" in first["body"]

    def test_draft(self, repo: Path, gh_calls: list[dict]):
        open_fix_prs(repo, [_result("f1", "settings.py", CFG, CFG_FIXED)], draft=True)
        assert "--draft" in gh_calls[0]["args"]

    def test_dirty_tree_refused(self, repo: Path, gh_calls: list[dict]):
        (repo / "settings.py").write_text("junk\n", encoding="utf-8")
        with pytest.raises(GitError, match="not clean"):
            open_fix_prs(repo, [_result("f1", "src/app.py", APP, APP_FIXED)])
        assert gh_calls == []

    def test_untracked_file_counts_as_dirty(self, repo: Path, gh_calls: list[dict]):
        (repo / "new.txt").write_text("x", encoding="utf-8")
        with pytest.raises(GitError, match="not clean"):
            open_fix_prs(repo, [_result("f1", "src/app.py", APP, APP_FIXED)])

    def test_existing_branch_gets_suffix(self, repo: Path, gh_calls: list[dict]):
        git(repo, "branch", "vulnsift/fix-f1")
        outcomes = open_fix_prs(repo, [_result("f1", "settings.py", CFG, CFG_FIXED)])
        assert outcomes[0][2] is None
        head = gh_calls[0]["args"][gh_calls[0]["args"].index("--head") + 1]
        assert head.startswith("vulnsift/fix-f1-") and len(head) == len("vulnsift/fix-f1-") + 6

    def test_push_failure_isolated(self, repo: Path, gh_calls: list[dict]):
        git(repo, "remote", "set-url", "origin", str(repo.parent / "missing.git"))
        outcomes = open_fix_prs(repo, [_result("f1", "settings.py", CFG, CFG_FIXED)])
        _, url, err = outcomes[0]
        assert url is None and err and "push" in err
        assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
        assert git(repo, "status", "--porcelain") == ""

    def test_gh_failure_isolated_and_continues(self, repo: Path, monkeypatch: pytest.MonkeyPatch):
        real_run = github_pr._run
        count = {"n": 0}

        def fake_run(args, cwd, *, input=None):
            if args[0] == "gh":
                count["n"] += 1
                if count["n"] == 1:
                    raise GitError("gh pr create failed: auth required")
                return "https://github.com/acme/app/pull/2"
            return real_run(args, cwd, input=input)

        monkeypatch.setattr(github_pr, "_run", fake_run)
        outcomes = open_fix_prs(
            repo,
            [_result("f1", "settings.py", CFG, CFG_FIXED), _result("f2", "src/app.py", APP, APP_FIXED)],
        )
        assert outcomes[0][1] is None and "auth" in (outcomes[0][2] or "")
        assert outcomes[1][1] == "https://github.com/acme/app/pull/2"
        assert git(repo, "status", "--porcelain") == ""

    def test_stale_patch_rejected(self, repo: Path, gh_calls: list[dict]):
        outcomes = open_fix_prs(repo, [_result("f1", "settings.py", "OTHER = 1\n", CFG_FIXED)])
        assert outcomes[0][1] is None and "differs" in (outcomes[0][2] or "")
        assert gh_calls == []
        assert git(repo, "branch", "--list", "vulnsift/*") == ""
        assert git(repo, "status", "--porcelain") == ""

    def test_traversal_rejected(self, repo: Path, gh_calls: list[dict]):
        outcomes = open_fix_prs(repo, [_result("f1", "../escape.py", CFG, CFG_FIXED)])
        assert "outside the repository" in (outcomes[0][2] or "")
        assert gh_calls == []

    def test_explicit_base_branch_and_restore(self, repo: Path, gh_calls: list[dict]):
        git(repo, "checkout", "-q", "-b", "feature")
        outcomes = open_fix_prs(repo, [_result("f1", "settings.py", CFG, CFG_FIXED)], base_branch="main")
        assert outcomes[0][2] is None
        assert gh_calls[0]["args"][gh_calls[0]["args"].index("--base") + 1] == "main"
        assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "feature"

    def test_detached_head_requires_base(self, repo: Path, gh_calls: list[dict]):
        git(repo, "checkout", "-q", "--detach")
        with pytest.raises(GitError, match="detached"):
            open_fix_prs(repo, [_result("f1", "settings.py", CFG, CFG_FIXED)])
        outcomes = open_fix_prs(repo, [_result("f1", "settings.py", CFG, CFG_FIXED)], base_branch="main")
        assert outcomes[0][2] is None
        assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "HEAD"


class TestPrBody:
    def test_truncates_large_diff(self):
        r = _result("f1", "a.py", "x\n" * 50_000, "y\n" * 50_000)
        body = build_pr_body(r, max_diff=1000)
        assert "truncated" in body
        assert len(body) < 3000

    def test_fence_survives_backticks_in_diff(self):
        r = _result("f1", "README.md", "```\ncode\n```\n", "````\ncode\n````\n")
        body = build_pr_body(r)
        assert "`````diff" in body


def test_safe_branch_id():
    assert safe_branch_id("semgrep:python/sql..injection") == "semgrep-python-sql-injection"
    assert safe_branch_id("///") == "finding"
    assert len(safe_branch_id("a" * 100)) == 40
