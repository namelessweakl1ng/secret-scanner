"""Scanner package: local, git, github, gitlab, bitbucket, archive, remote."""

from __future__ import annotations

from .archive import ArchiveScanner
from .git_scanner import GitScanner
from .local import LocalScanner
from .remote import (
    BitbucketScanner,
    GistScanner,
    GitHubScanner,
    GitLabScanner,
    RawURLScanner,
    parse_repo_url,
)

__all__ = [
    "LocalScanner",
    "ArchiveScanner",
    "GitScanner",
    "GitHubScanner",
    "GitLabScanner",
    "BitbucketScanner",
    "GistScanner",
    "RawURLScanner",
    "parse_repo_url",
]
