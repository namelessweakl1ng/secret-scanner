"""Remote scanners: GitHub, GitLab, Bitbucket, Gist.

These work by cloning the target repo to a temp dir (with optional auth via
environment variables), scanning it with the GitScanner, then securely
deleting the temp dir. This avoids needing API tokens for read access to
public repos and keeps the implementation simple and uniform.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from ..config import ScanConfig
from ..detectors import Engine
from ..git import GitError, clone
from ..models import ScanResult
from ..utils.fileio import make_temp_dir, secure_delete
from .git_scanner import GitScanner

# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------

_GITHUB_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+?)(?:\.git)?(?:/|$)"
)
_GITLAB_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?gitlab\.com/(?P<path>[^/\s]+/[^/\s]+(?:/[^/\s]+)*?)(?:\.git)?(?:/|$)"
)
_BITBUCKET_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?bitbucket\.org/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+?)(?:\.git)?(?:/|$)"
)
_GIST_URL = re.compile(r"^(?:https?://)?gist\.github\.com/(?P<owner>[^/\s]+)/(?P<id>[a-f0-9]+)")


def parse_repo_url(url: str) -> tuple[str, str]:
    """Parse a repo URL into (kind, normalized_clone_url).

    kind is one of: 'github', 'gitlab', 'bitbucket', 'gist', 'unknown'.
    For 'unknown', the URL is returned as-is for direct git cloning.
    """
    url = url.strip()
    if not url:
        raise ValueError("Empty URL")

    # shorthand owner/repo for github
    if re.fullmatch(r"[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+", url):
        return ("github", f"https://github.com/{url}.git")

    if _GITHUB_URL.match(url):
        return ("github", _ensure_git_suffix(url))
    if _GITLAB_URL.match(url):
        return ("gitlab", _ensure_git_suffix(url))
    if _BITBUCKET_URL.match(url):
        return ("bitbucket", _ensure_git_suffix(url))
    if _GIST_URL.match(url):
        m = _GIST_URL.match(url)
        assert m is not None
        gid = m.group("id")
        return ("gist", f"https://gist.github.com/{gid}.git")

    # Generic git URL.
    return ("unknown", url)


def _ensure_git_suffix(url: str) -> str:
    if url.endswith(".git"):
        return url
    # Strip trailing slash and query/fragment.
    cleaned = url.split("?")[0].split("#")[0].rstrip("/")
    return cleaned + ".git"


def _inject_token(url: str, token: str | None, host: str = "github.com") -> str:
    """Inject an OAuth token into a URL for authenticated cloning."""
    if not token:
        return url
    parsed = urlparse(url)
    if not parsed.netloc:
        return url
    # Use the form https://<token>@host/path (works for GitHub, GitLab).
    return f"{parsed.scheme}://{token}@{parsed.netloc}{parsed.path}"


# ---------------------------------------------------------------------------
# GitHub scanner
# ---------------------------------------------------------------------------


class GitHubScanner:
    """Scan a GitHub repository (public or private via GITHUB_TOKEN)."""

    def __init__(
        self, config: ScanConfig, engine: Engine | None = None, *, show_progress: bool = True
    ) -> None:
        self.config = config
        self.engine = engine or Engine(config.ruleset)
        self.show_progress = show_progress

    def scan(self, repo: str, *, scan_history: bool = True, depth: int | None = None) -> ScanResult:
        """Scan a GitHub repo. ``repo`` can be owner/repo or a full URL."""
        kind, url = parse_repo_url(repo)
        if kind != "github":
            raise ValueError(f"Not a GitHub URL: {repo}")

        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        clone_url = _inject_token(url, token, "github.com")

        result = ScanResult(target=repo, scan_type="github")
        tmp = make_temp_dir(prefix="ss-github-")
        try:
            clone(clone_url, tmp, depth=depth)
            scanner = GitScanner(
                self.config,
                self.engine,
                show_progress=self.show_progress,
                scan_history=scan_history,
                scan_blame=False,
                commit_limit=depth * 5 if depth else None,
            )
            sub = scanner.scan(tmp)
            # Rewrite paths to be repo-relative with the repo name prefix.
            repo_name = repo.rstrip("/").split("/")[-1].removesuffix(".git")
            for f in sub.findings:
                f.file_path = f"{repo_name}/{f.file_path}"
            result.findings.extend(sub.findings)
            result.files_scanned += sub.files_scanned
            result.files_skipped += sub.files_skipped
            result.errors.extend(sub.errors)
        except GitError as exc:
            result.errors.append(str(exc))
        finally:
            secure_delete(tmp)

        result.finished_at = datetime.now(UTC)
        return result


# ---------------------------------------------------------------------------
# GitLab scanner
# ---------------------------------------------------------------------------


class GitLabScanner:
    """Scan a GitLab repository (public or private via GITLAB_TOKEN)."""

    def __init__(
        self, config: ScanConfig, engine: Engine | None = None, *, show_progress: bool = True
    ) -> None:
        self.config = config
        self.engine = engine or Engine(config.ruleset)
        self.show_progress = show_progress

    def scan(self, repo: str, *, scan_history: bool = True, depth: int | None = None) -> ScanResult:
        kind, url = parse_repo_url(repo)
        if kind != "gitlab":
            raise ValueError(f"Not a GitLab URL: {repo}")

        token = os.environ.get("GITLAB_TOKEN") or os.environ.get("GITLAB_PRIVATE_TOKEN")
        # GitLab uses "oauth2:<token>" or just "<token>" for HTTPS auth.
        clone_url = _inject_token(url, token, "gitlab.com")

        result = ScanResult(target=repo, scan_type="gitlab")
        tmp = make_temp_dir(prefix="ss-gitlab-")
        try:
            clone(clone_url, tmp, depth=depth)
            scanner = GitScanner(
                self.config,
                self.engine,
                show_progress=self.show_progress,
                scan_history=scan_history,
                commit_limit=depth * 5 if depth else None,
            )
            sub = scanner.scan(tmp)
            repo_name = repo.rstrip("/").split("/")[-1].removesuffix(".git")
            for f in sub.findings:
                f.file_path = f"{repo_name}/{f.file_path}"
            result.findings.extend(sub.findings)
            result.files_scanned += sub.files_scanned
            result.files_skipped += sub.files_skipped
            result.errors.extend(sub.errors)
        except GitError as exc:
            result.errors.append(str(exc))
        finally:
            secure_delete(tmp)

        result.finished_at = datetime.now(UTC)
        return result


# ---------------------------------------------------------------------------
# Bitbucket scanner
# ---------------------------------------------------------------------------


class BitbucketScanner:
    """Scan a Bitbucket repository (public or private via BITBUCKET_TOKEN)."""

    def __init__(
        self, config: ScanConfig, engine: Engine | None = None, *, show_progress: bool = True
    ) -> None:
        self.config = config
        self.engine = engine or Engine(config.ruleset)
        self.show_progress = show_progress

    def scan(self, repo: str, *, scan_history: bool = True, depth: int | None = None) -> ScanResult:
        kind, url = parse_repo_url(repo)
        if kind != "bitbucket":
            raise ValueError(f"Not a Bitbucket URL: {repo}")

        token = os.environ.get("BITBUCKET_TOKEN") or os.environ.get("BITBUCKET_APP_PASSWORD")
        user = os.environ.get("BITBUCKET_USERNAME", "")
        if token and user:
            # Bitbucket uses basic auth: https://user:token@host
            parsed = urlparse(url)
            clone_url = f"{parsed.scheme}://{user}:{token}@{parsed.netloc}{parsed.path}"
        else:
            clone_url = _inject_token(url, token, "bitbucket.org")

        result = ScanResult(target=repo, scan_type="bitbucket")
        tmp = make_temp_dir(prefix="ss-bitbucket-")
        try:
            clone(clone_url, tmp, depth=depth)
            scanner = GitScanner(
                self.config,
                self.engine,
                show_progress=self.show_progress,
                scan_history=scan_history,
                commit_limit=depth * 5 if depth else None,
            )
            sub = scanner.scan(tmp)
            repo_name = repo.rstrip("/").split("/")[-1].removesuffix(".git")
            for f in sub.findings:
                f.file_path = f"{repo_name}/{f.file_path}"
            result.findings.extend(sub.findings)
            result.files_scanned += sub.files_scanned
            result.files_skipped += sub.files_skipped
            result.errors.extend(sub.errors)
        except GitError as exc:
            result.errors.append(str(exc))
        finally:
            secure_delete(tmp)

        result.finished_at = datetime.now(UTC)
        return result


# ---------------------------------------------------------------------------
# Gist scanner
# ---------------------------------------------------------------------------


class GistScanner:
    """Scan a GitHub gist."""

    def __init__(
        self, config: ScanConfig, engine: Engine | None = None, *, show_progress: bool = True
    ) -> None:
        self.config = config
        self.engine = engine or Engine(config.ruleset)
        self.show_progress = show_progress

    def scan(self, gist_url_or_id: str) -> ScanResult:
        """Scan a gist by URL or ID."""
        kind, url = (
            parse_repo_url(gist_url_or_id)
            if "gist.github.com" in gist_url_or_id
            else ("gist", f"https://gist.github.com/{gist_url_or_id}.git")
        )
        if kind != "gist":
            url = f"https://gist.github.com/{gist_url_or_id}.git"

        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        clone_url = _inject_token(url, token, "gist.github.com")

        result = ScanResult(target=gist_url_or_id, scan_type="gist")
        tmp = make_temp_dir(prefix="ss-gist-")
        try:
            clone(clone_url, tmp)
            # Gists usually have no history worth scanning — just scan the files.
            from .local import LocalScanner

            local = LocalScanner(self.config, self.engine, show_progress=False)
            sub = local.scan(tmp)
            for f in sub.findings:
                # Remove tmp dir prefix.
                try:
                    rel = Path(f.file_path).relative_to(tmp)
                    f.file_path = f"gist/{rel}"
                except ValueError:
                    pass
            result.findings.extend(sub.findings)
            result.files_scanned += sub.files_scanned
            result.files_skipped += sub.files_skipped
            result.errors.extend(sub.errors)
        except GitError as exc:
            result.errors.append(str(exc))
        finally:
            secure_delete(tmp)

        result.finished_at = datetime.now(UTC)
        return result


# ---------------------------------------------------------------------------
# Raw URL scanner
# ---------------------------------------------------------------------------


class RawURLScanner:
    """Download a single file from a URL and scan it."""

    def __init__(self, config: ScanConfig, engine: Engine | None = None) -> None:
        self.config = config
        self.engine = engine or Engine(config.ruleset)

    def scan(self, url: str) -> ScanResult:
        """Download and scan a single file from a URL."""
        import httpx

        result = ScanResult(target=url, scan_type="url")
        try:
            resp = httpx.get(url, timeout=30.0, follow_redirects=True)
            resp.raise_for_status()
            content = resp.text
        except (httpx.HTTPError, httpx.RequestError) as exc:
            result.errors.append(f"Download failed: {exc}")
            result.finished_at = datetime.now(UTC)
            return result

        # Save to temp file so we can reuse the line scanner.
        tmp = make_temp_dir(prefix="ss-url-") / "download"
        try:
            tmp.write_text(content, encoding="utf-8", errors="replace")
            from .local import LocalScanner

            local = LocalScanner(self.config, self.engine, show_progress=False)
            sub = local.scan(tmp)
            for f in sub.findings:
                f.file_path = (
                    f"{url}:{f.file_path.split(':')[-1] if ':' in f.file_path else ''}".rstrip(":")
                )
            result.findings.extend(sub.findings)
            result.files_scanned += sub.files_scanned
        finally:
            secure_delete(tmp.parent)

        result.finished_at = datetime.now(UTC)
        return result


__all__ = [
    "GitHubScanner",
    "GitLabScanner",
    "BitbucketScanner",
    "GistScanner",
    "RawURLScanner",
    "parse_repo_url",
]
