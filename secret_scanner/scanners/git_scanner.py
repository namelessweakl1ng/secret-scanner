"""Git history scanner: scans current files, all commits, branches, stashes."""

from __future__ import annotations

import contextlib
import re
from datetime import UTC, datetime
from pathlib import Path

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from ..config import ScanConfig
from ..detectors import Engine, ScanContext
from ..git import (
    blame_line,
    is_git_repo,
    list_branches,
    list_commits,
    list_files_at_ref,
    list_stashes,
    list_tags,
    show_file_at_ref,
)
from ..models import Finding, ScanResult

# Skip these paths when scanning git history (binary / generated).
_PATH_SKIP_RE = re.compile(
    r"^("
    r"\.git/|"
    r"node_modules/|"
    r"vendor/|"
    r"dist/|"
    r"build/|"
    r"target/|"
    r"\.venv/|"
    r"venv/|"
    r"__pycache__/|"
    r".*\.(png|jpg|jpeg|gif|bmp|ico|webp|tiff|tif|mp3|mp4|avi|mov|mkv|wav|flac|ogg|webm|pdf|doc|docx|xls|xlsx|ppt|pptx|class|pyc|pyo|o|so|dll|dylib|exe|bin|wasm|dex|woff|woff2|ttf|otf|eot|sqlite|db|mdb|jar|war|ear|apk|ipa|xpi|crx)"
    r")",
    re.IGNORECASE,
)


class GitScanner:
    """Scan a git repository: working tree + all history + branches + stashes."""

    def __init__(
        self,
        config: ScanConfig,
        engine: Engine | None = None,
        *,
        show_progress: bool = True,
        scan_history: bool = True,
        scan_branches: bool = True,
        scan_tags: bool = False,
        scan_stashes: bool = True,
        scan_blame: bool = False,
        commit_limit: int | None = None,
    ) -> None:
        self.config = config
        self.engine = engine or Engine(config.ruleset)
        self.show_progress = show_progress
        self.scan_history = scan_history
        self.scan_branches = scan_branches
        self.scan_tags = scan_tags
        self.scan_stashes = scan_stashes
        self.scan_blame = scan_blame
        self.commit_limit = commit_limit

    def scan(self, target: str | Path) -> ScanResult:
        """Scan a git repo at ``target``.

        If ``scan_history`` is True (default), walks every commit and looks
        at every file at every revision. This is O(commits * files) but
        necessary to catch secrets in deleted files.
        """
        target = Path(target).resolve()
        result = ScanResult(target=str(target), scan_type="git")

        if not is_git_repo(target):
            result.errors.append(f"Not a git repository: {target}")
            result.finished_at = datetime.now(UTC)
            return result

        # Phase 1: working tree (uses the local scanner).
        from .local import LocalScanner

        local = LocalScanner(self.config, self.engine, show_progress=False)
        working_result = local.scan(target)
        # Strip out path-based findings that are duplicate of history scan
        # (we already cover them in the working tree).
        result.findings.extend(working_result.findings)
        result.files_scanned += working_result.files_scanned
        result.files_skipped += working_result.files_skipped
        result.errors.extend(working_result.errors)

        if self.scan_history:
            self._scan_history(target, result)

        # Filter baseline.
        if self.config.baseline_fingerprints:
            result.findings = [
                f for f in result.findings if f.fingerprint not in self.config.baseline_fingerprints
            ]

        # Deduplicate findings with the same (file, line, fingerprint).
        result.findings = _dedupe(result.findings)

        result.finished_at = datetime.now(UTC)
        return result

    def _scan_history(self, root: Path, result: ScanResult) -> None:
        """Scan all commits across all refs."""
        refs: list[str] = ["HEAD"]
        if self.scan_branches:
            refs.extend(list_branches(root))
        if self.scan_tags:
            refs.extend(list_tags(root))
        if self.scan_stashes:
            refs.extend(list_stashes(root))
        # Deduplicate refs.
        refs = list(dict.fromkeys(refs))

        # Collect all commits across refs.
        all_commits: list[str] = []
        seen: set[str] = set()
        for ref in refs:
            for sha in list_commits(root, ref=ref, limit=self.commit_limit):
                if sha not in seen:
                    seen.add(sha)
                    all_commits.append(sha)

        progress = self._make_progress()
        with progress if self.show_progress else _NullCtx() as p:
            task_id = (
                p.add_task("Scanning history", total=len(all_commits))
                if self.show_progress
                else None
            )
            for sha in all_commits:
                try:
                    self._scan_commit(root, sha, result)
                except Exception as exc:  # noqa: BLE001
                    result.errors.append(f"commit {sha}: {exc}")
                if self.show_progress and task_id is not None:
                    p.advance(task_id)

    def _scan_commit(self, root: Path, sha: str, result: ScanResult) -> None:
        """Scan every file at a given commit."""
        files = list_files_at_ref(root, sha)
        for rel_path in files:
            if _PATH_SKIP_RE.match(rel_path):
                continue
            content = show_file_at_ref(root, sha, rel_path)
            if content is None:
                continue
            # Apply file size limit.
            if len(content) > self.config.max_file_size_mb * 1024 * 1024:
                continue
            # Path-based finding.
            for f in self.engine.scan_file_path(rel_path):
                f.file_path = f"{rel_path}@{sha[:8]}"
                f.commit_sha = sha
                result.findings.append(f)
                result.files_scanned += 1
            # Line-by-line.
            for i, line in enumerate(content.splitlines(), start=1):
                ctx = ScanContext(
                    file_path=rel_path,
                    line_number=i,
                    line_text=line,
                    full_text=content,
                )
                for finding in self.engine.scan_line(line, ctx):
                    finding.file_path = f"{rel_path}@{sha[:8]}"
                    finding.commit_sha = sha
                    if self.scan_blame and finding.line_number:
                        blame = blame_line(root, rel_path, finding.line_number)
                        if blame:
                            finding.commit_author = f"{blame.author} <{blame.author_email}>"
                            with contextlib.suppress(ValueError):
                                finding.commit_date = datetime.fromisoformat(blame.date)
                    result.findings.append(finding)
            result.files_scanned += 1

    def _make_progress(self) -> Progress:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            transient=True,
        )


class _NullCtx:
    def __enter__(self) -> _NullProgress:
        return _NullProgress()

    def __exit__(self, *exc) -> None:  # noqa: ANN001
        return None


class _NullProgress:
    def add_task(self, *a, **k):  # noqa: ANN001, ANN002, ANN003
        return None

    def advance(self, *a, **k):  # noqa: ANN001, ANN002, ANN003
        return None


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by (file_path, line_number, fingerprint)."""
    seen: set[tuple[str, int, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.file_path, f.line_number, f.fingerprint)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


__all__ = ["GitScanner"]
