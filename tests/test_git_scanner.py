"""Tests for git utilities and the git history scanner.

Uses a real temporary git repo (created via subprocess) so we exercise the
actual git CLI path. All test secrets use ``SAMPLES`` (runtime-constructed)
so that no literal real-format secret pattern appears in the source file.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from secret_scanner.config import ScanConfig
from secret_scanner.detectors import Engine
from secret_scanner.git import (
    GitError,
    blame_line,
    git_root,
    is_git_repo,
    list_branches,
    list_commits,
    list_files_at_ref,
    list_stashes,
    list_tags,
    show_file_at_ref,
)
from secret_scanner.scanners import GitScanner

from .samples import SAMPLES


def _git(path: Path, *args: str, **env) -> str:  # noqa: ANN001
    """Run a git command in `path` and return stdout."""
    full_env = os.environ.copy()
    full_env.update(
        {
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
    )
    full_env.update(env)
    result = subprocess.run(
        ["git", "-C", str(path), *args],
        capture_output=True,
        text=True,
        env=full_env,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {args} failed: {result.stderr}")
    return result.stdout


def _make_repo(tmp_path: Path) -> Path:
    """Create a real git repo with one commit containing a secret."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "config.py").write_text(f'KEY = "{SAMPLES["aws_access_key_id"]}"\n')
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")
    return repo


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Pytest fixture returning a git repo with a secret in the initial commit."""
    return _make_repo(tmp_path)


def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


pytestmark = pytest.mark.skipif(not _git_available(), reason="git not installed")


class TestGitUtilities:
    def test_is_git_repo_true(self, git_repo: Path) -> None:
        assert is_git_repo(git_repo)

    def test_is_git_repo_false(self, tmp_path: Path) -> None:
        assert not is_git_repo(tmp_path)

    def test_git_root(self, git_repo: Path) -> None:
        root = git_root(git_repo)
        assert root.resolve() == git_repo.resolve()

    def test_git_root_not_repo(self, tmp_path: Path) -> None:
        with pytest.raises(GitError):
            git_root(tmp_path)

    def test_list_commits(self, git_repo: Path) -> None:
        commits = list_commits(git_repo)
        assert len(commits) == 1

    def test_list_commits_with_limit(self, git_repo: Path) -> None:
        commits = list_commits(git_repo, limit=10)
        assert len(commits) == 1

    def test_list_branches(self, git_repo: Path) -> None:
        branches = list_branches(git_repo)
        # Default branch is master or main.
        assert any("master" in b or "main" in b for b in branches)

    def test_list_tags_empty(self, git_repo: Path) -> None:
        assert list_tags(git_repo) == []

    def test_list_stashes_empty(self, git_repo: Path) -> None:
        assert list_stashes(git_repo) == []

    def test_list_files_at_ref(self, git_repo: Path) -> None:
        files = list_files_at_ref(git_repo, "HEAD")
        assert "config.py" in files

    def test_show_file_at_ref(self, git_repo: Path) -> None:
        content = show_file_at_ref(git_repo, "HEAD", "config.py")
        assert content is not None
        assert SAMPLES["aws_access_key_id"] in content

    def test_show_file_at_ref_missing(self, git_repo: Path) -> None:
        assert show_file_at_ref(git_repo, "HEAD", "nope.py") is None

    def test_blame_line(self, git_repo: Path) -> None:
        info = blame_line(git_repo, "config.py", 1)
        assert info is not None
        assert info.author == "Test"


class TestGitScanner:
    def test_scan_repo(self, git_repo: Path) -> None:
        cfg = ScanConfig()
        cfg.apply_overrides()
        eng = Engine(cfg.ruleset)
        scanner = GitScanner(cfg, eng, show_progress=False, scan_history=True)
        result = scanner.scan(git_repo)
        # The AWS key in config.py should be detected.
        assert any(f.rule_id == "aws_access_key_id" for f in result.findings)
        # Commit attribution should be present on history findings.
        history = [f for f in result.findings if f.commit_sha]
        assert len(history) >= 1

    def test_scan_non_git_path(self, tmp_path: Path) -> None:
        cfg = ScanConfig()
        eng = Engine(cfg.ruleset)
        scanner = GitScanner(cfg, eng, show_progress=False)
        result = scanner.scan(tmp_path)
        assert len(result.errors) >= 1
