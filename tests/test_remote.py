"""Tests for remote scanner URL parsing (no network access)."""

from __future__ import annotations

import pytest

from secret_scanner.scanners.remote import _ensure_git_suffix, _inject_token, parse_repo_url


class TestParseRepoURL:
    def test_github_shorthand(self) -> None:
        kind, url = parse_repo_url("owner/repo")
        assert kind == "github"
        assert "github.com/owner/repo" in url
        assert url.endswith(".git")

    def test_github_https_url(self) -> None:
        kind, url = parse_repo_url("https://github.com/owner/repo")
        assert kind == "github"
        assert url.endswith(".git")

    def test_github_url_with_trailing_slash(self) -> None:
        kind, url = parse_repo_url("https://github.com/owner/repo/")
        assert kind == "github"
        assert url == "https://github.com/owner/repo.git"

    def test_github_url_already_has_git(self) -> None:
        kind, url = parse_repo_url("https://github.com/owner/repo.git")
        assert kind == "github"
        assert url == "https://github.com/owner/repo.git"

    def test_gitlab_url(self) -> None:
        kind, url = parse_repo_url("https://gitlab.com/group/project")
        assert kind == "gitlab"

    def test_gitlab_nested_group(self) -> None:
        kind, url = parse_repo_url("https://gitlab.com/group/subgroup/project")
        assert kind == "gitlab"

    def test_bitbucket_url(self) -> None:
        kind, url = parse_repo_url("https://bitbucket.org/owner/repo")
        assert kind == "bitbucket"

    def test_gist_url(self) -> None:
        kind, url = parse_repo_url("https://gist.github.com/user/abc123def456")
        assert kind == "gist"
        assert "abc123def456" in url

    def test_unknown_url(self) -> None:
        kind, url = parse_repo_url("https://example.com/repo.git")
        assert kind == "unknown"
        assert url == "https://example.com/repo.git"

    def test_empty_url_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_repo_url("")

    def test_github_url_with_query_string(self) -> None:
        kind, url = parse_repo_url("https://github.com/owner/repo?tab=README")
        assert kind == "github"
        assert "?tab" not in url
        assert url.endswith(".git")


class TestInjectToken:
    def test_with_token(self) -> None:
        url = _inject_token("https://github.com/owner/repo.git", "ghp_xxx", "github.com")
        assert "ghp_xxx@" in url

    def test_without_token(self) -> None:
        url = _inject_token("https://github.com/owner/repo.git", None, "github.com")
        assert "@" not in url.split("//")[1].split("/")[0]

    def test_preserves_path(self) -> None:
        url = _inject_token("https://github.com/o/r.git", "tok", "github.com")
        assert url.endswith("o/r.git")


class TestEnsureGitSuffix:
    def test_adds_suffix(self) -> None:
        assert _ensure_git_suffix("https://x.com/o/r") == "https://x.com/o/r.git"

    def test_keeps_suffix(self) -> None:
        assert _ensure_git_suffix("https://x.com/o/r.git") == "https://x.com/o/r.git"

    def test_strips_query(self) -> None:
        assert _ensure_git_suffix("https://x.com/o/r?foo=bar") == "https://x.com/o/r.git"

    def test_strips_fragment(self) -> None:
        assert _ensure_git_suffix("https://x.com/o/r#readme") == "https://x.com/o/r.git"
