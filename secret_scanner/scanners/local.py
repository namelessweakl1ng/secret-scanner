"""Local filesystem scanner.

Scans directories (recursively), individual files, and handles archives.
Designed for parallelism: each file is scanned independently in a worker
thread via :class:`concurrent.futures.ThreadPoolExecutor`.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC
from pathlib import Path

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from ..config import ScanConfig
from ..detectors import Engine, ScanContext
from ..models import Finding, ScanResult
from ..utils.fileio import (
    is_archive,
    is_binary_file,
    read_text_lines,
)
from ..utils.ignore import IgnoreMatcher


class LocalScanner:
    """Scan local files and directories."""

    def __init__(
        self,
        config: ScanConfig,
        engine: Engine | None = None,
        *,
        show_progress: bool = True,
    ) -> None:
        self.config = config
        self.engine = engine or Engine(
            config.ruleset,
            min_entropy=config.min_entropy,
            min_length=config.min_length,
            max_length=config.max_length,
            max_line_length=config.max_line_length,
            enable_entropy=config.enable_entropy,
            enable_context=config.enable_context,
            enable_path_rules=config.enable_path_rules,
        )
        self.show_progress = show_progress

    def scan(self, target: str | Path) -> ScanResult:
        """Scan a file or directory and return a :class:`ScanResult`."""
        target = Path(target).resolve()
        result = ScanResult(target=str(target), scan_type="local")
        if not target.exists():
            result.errors.append(f"Path does not exist: {target}")
            result.finished_at = _now()
            return result

        if target.is_file():
            self._scan_single_file(target, result)
        else:
            self._scan_directory(target, result)

        # Filter out baseline-suppressed findings.
        if self.config.baseline_fingerprints:
            result.findings = [
                f for f in result.findings if f.fingerprint not in self.config.baseline_fingerprints
            ]

        result.finished_at = _now()
        return result

    # ------------------------------------------------------------------
    # Directory scanning
    # ------------------------------------------------------------------

    def _scan_directory(self, root: Path, result: ScanResult) -> None:
        """Walk a directory and scan all text files in parallel."""
        ignore = IgnoreMatcher(
            base_dir=root,
            use_gitignore=self.config.use_gitignore,
            glob_patterns=self.config.ignore_globs,
            regex_patterns=self.config.ignore_regexes,
        )

        # First pass: collect candidate files.
        files_to_scan: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=self.config.follow_symlinks):
            dir_path = Path(dirpath)
            # Filter ignored dirs in-place to skip traversal.
            dirnames[:] = [d for d in dirnames if not ignore.is_ignored(dir_path / d)]
            for fname in filenames:
                fpath = dir_path / fname
                if ignore.is_ignored(fpath):
                    result.files_skipped += 1
                    continue
                if is_archive(fpath):
                    # Will be handled separately below; still count.
                    files_to_scan.append(fpath)
                elif is_binary_file(fpath):
                    result.files_skipped += 1
                    continue
                else:
                    files_to_scan.append(fpath)

        # Scan with a progress bar.
        progress = self._make_progress()
        with progress if self.show_progress else _NullCtx() as p:
            task_id = (
                p.add_task(f"Scanning {root.name or root}", total=len(files_to_scan))
                if self.show_progress
                else None
            )

            with ThreadPoolExecutor(max_workers=self.config.workers) as pool:
                futures = {
                    pool.submit(self._scan_file_worker, fpath, root): fpath
                    for fpath in files_to_scan
                }
                for fut in as_completed(futures):
                    fpath = futures[fut]
                    try:
                        findings = fut.result()
                        result.findings.extend(findings)
                    except Exception as exc:  # noqa: BLE001
                        result.errors.append(f"{fpath}: {exc}")
                    finally:
                        if self.show_progress and task_id is not None:
                            p.advance(task_id)

    def _scan_file_worker(self, path: Path, root: Path) -> list[Finding]:
        """Worker: scan a single file (or recurse into an archive)."""
        if is_archive(path):
            from .archive import ArchiveScanner

            return (
                ArchiveScanner(self.config, self.engine, show_progress=False)
                .scan_archive_file(path)
                .findings
            )
        return self._scan_text_file(path, root)

    def _scan_text_file(self, path: Path, root: Path) -> list[Finding]:
        """Scan a single text file."""
        findings: list[Finding] = []
        try:
            size = path.stat().st_size
        except OSError:
            return findings
        if size > self.config.max_file_size_mb * 1024 * 1024:
            return findings

        # Path-based rules.
        findings.extend(self.engine.scan_file_path(str(path)))

        # Line-by-line.
        for i, line in enumerate(read_text_lines(path), start=1):
            ctx = ScanContext(
                file_path=str(path),
                line_number=i,
                line_text=line,
                file_extension=path.suffix,
            )
            findings.extend(self.engine.scan_line(line, ctx))
        return findings

    def _scan_single_file(self, path: Path, result: ScanResult) -> None:
        """Scan a single file (target was a file, not a directory)."""
        result.files_scanned = 1
        if is_archive(path):
            sub = self._archive_scanner.scan_archive_file(path)
            result.findings.extend(sub.findings)
            result.files_scanned += sub.files_scanned
            result.errors.extend(sub.errors)
            return
        if is_binary_file(path):
            result.files_skipped = 1
            return
        result.findings.extend(self._scan_text_file(path, path.parent))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_progress(self) -> Progress:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            transient=True,
        )


class _NullCtx:
    """Null context manager that no-ops progress calls when progress is off."""

    def __enter__(self) -> _NullProgress:
        return _NullProgress()

    def __exit__(self, *exc) -> None:  # noqa: ANN001
        return None


class _NullProgress:
    """Stub Progress-like object for when show_progress=False."""

    def add_task(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return None

    def advance(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return None

    def update(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return None


def _now():
    from datetime import datetime

    return datetime.now(UTC)


__all__ = ["LocalScanner"]
