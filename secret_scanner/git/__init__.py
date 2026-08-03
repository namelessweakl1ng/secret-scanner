"""Git utilities: history scanning, blame, branch enumeration.

Uses ``git`` via subprocess so we don't require GitPython (which can be slow
on very large repos). Falls back gracefully when ``git`` is not installed.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


class GitError(RuntimeError):
    """Raised when a git operation fails."""


@dataclass(frozen=True)
class CommitInfo:
    """Minimal commit metadata for blame/history attribution."""

    sha: str
    author: str
    author_email: str
    date: str  # ISO 8601


def is_git_repo(path: Path) -> bool:
    """Return True if ``path`` is inside a git work tree."""
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def git_root(path: Path) -> Path:
    """Return the root of the git work tree."""
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise GitError(f"Not a git repo: {path}")
    return Path(result.stdout.strip())


def list_commits(path: Path, *, limit: int | None = None, ref: str = "HEAD") -> list[str]:
    """List commit SHAs in chronological order (oldest first)."""
    cmd = ["git", "-C", str(path), "log", "--reverse", "--format=%H", ref]
    if limit:
        cmd.append(f"-n{limit}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def list_branches(path: Path) -> list[str]:
    """List all branches (local + remote)."""
    result = subprocess.run(
        ["git", "-C", str(path), "branch", "-a", "--format=%(refname:short)"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def list_tags(path: Path) -> list[str]:
    """List all tags."""
    result = subprocess.run(
        ["git", "-C", str(path), "tag", "--list"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def list_stashes(path: Path) -> list[str]:
    """List stash ref names."""
    result = subprocess.run(
        ["git", "-C", str(path), "stash", "list", "--format=%gd"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def show_file_at_ref(path: Path, ref: str, file_path: str) -> str | None:
    """Return the contents of ``file_path`` at ``ref``, or None if missing."""
    result = subprocess.run(
        ["git", "-C", str(path), "show", f"{ref}:{file_path}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        return result.stdout.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return None


def list_files_at_ref(path: Path, ref: str) -> list[str]:
    """List all files (relative paths) present at ``ref``."""
    result = subprocess.run(
        ["git", "-C", str(path), "ls-tree", "-r", "--name-only", ref],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def get_commit_info(path: Path, sha: str) -> CommitInfo | None:
    """Return commit metadata for a SHA."""
    result = subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "show",
            "-s",
            "--format=%H%n%an%n%ae%n%aI",
            sha,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    lines = result.stdout.splitlines()
    if len(lines) < 4:
        return None
    return CommitInfo(
        sha=lines[0].strip(),
        author=lines[1].strip(),
        author_email=lines[2].strip(),
        date=lines[3].strip(),
    )


def blame_line(path: Path, file_path: str, line_number: int) -> CommitInfo | None:
    """Return the commit that introduced ``line_number`` of ``file_path``."""
    result = subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "blame",
            "-L",
            f"{line_number},{line_number}",
            "--porcelain",
            "--",
            file_path,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    # First line: "<sha> <orig-line> <final-line>"
    first = result.stdout.splitlines()
    if not first:
        return None
    sha = first[0].split()[0]
    if sha in ("0000000000000000000000000000000000000000",):
        return None
    return get_commit_info(path, sha)


def clone(repo_url: str, dest: Path, *, depth: int | None = None, quiet: bool = True) -> None:
    """Clone a repo URL into ``dest``."""
    cmd = ["git", "clone"]
    if depth:
        cmd.extend(["--depth", str(depth)])
    if quiet:
        cmd.append("--quiet")
    cmd.extend([repo_url, str(dest)])
    env = os.environ.copy()
    # Disable interactive credential prompts.
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = ""
    env["SSH_ASKPASS"] = ""
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
    if result.returncode != 0:
        raise GitError(f"git clone failed: {result.stderr.strip()}")


__all__ = [
    "GitError",
    "CommitInfo",
    "is_git_repo",
    "git_root",
    "list_commits",
    "list_branches",
    "list_tags",
    "list_stashes",
    "show_file_at_ref",
    "list_files_at_ref",
    "get_commit_info",
    "blame_line",
    "clone",
]
