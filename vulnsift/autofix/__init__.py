"""Auto-fix agent: generate patches for triaged vulnerabilities."""

from vulnsift.autofix.agent import (
    DEFAULT_MIN_CONFIDENCE,
    MAX_SOURCE_SIZE,
    autofix_finding,
    autofix_report,
    filter_eligible,
)
from vulnsift.autofix.github_pr import GitError, build_pr_body, open_fix_prs
from vulnsift.autofix.patches import PatchError, UnsafePathError, generate_diff

__all__ = [
    "DEFAULT_MIN_CONFIDENCE",
    "MAX_SOURCE_SIZE",
    "GitError",
    "PatchError",
    "UnsafePathError",
    "autofix_finding",
    "autofix_report",
    "build_pr_body",
    "filter_eligible",
    "generate_diff",
    "open_fix_prs",
]
