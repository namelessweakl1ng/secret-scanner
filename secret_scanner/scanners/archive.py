"""Archive scanner: extract safely, scan, then securely delete."""

from __future__ import annotations

from datetime import UTC
from pathlib import Path

from ..config import ScanConfig
from ..detectors import Engine
from ..models import ScanResult
from ..utils.fileio import (
    make_temp_dir,
    safe_extract_tar,
    safe_extract_zip,
    secure_delete,
)
from .local import LocalScanner


class ArchiveScanner:
    """Scan archives (ZIP, JAR, WAR, APK, TAR, GZ, etc.)."""

    SUPPORTED = {
        ".zip",
        ".jar",
        ".war",
        ".ear",
        ".apk",
        ".ipa",
        ".xpi",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
    }

    def __init__(
        self,
        config: ScanConfig,
        engine: Engine | None = None,
        *,
        show_progress: bool = True,
    ) -> None:
        self.config = config
        self.engine = engine or Engine(config.ruleset)
        self.show_progress = show_progress

    def scan_archive_file(self, archive_path: Path) -> ScanResult:
        """Extract an archive to a temp dir, scan it, then securely delete."""
        result = ScanResult(
            target=str(archive_path),
            scan_type="archive",
        )

        ext = archive_path.suffix.lower()
        if ext not in self.SUPPORTED:
            result.errors.append(f"Unsupported archive type: {ext}")
            result.finished_at = _now()
            return result

        tmp_dir = make_temp_dir(prefix="ss-archive-")
        try:
            # Extract safely.
            try:
                if ext in {".zip", ".jar", ".war", ".ear", ".apk", ".ipa", ".xpi"}:
                    safe_extract_zip(archive_path, tmp_dir)
                else:
                    safe_extract_tar(archive_path, tmp_dir)
            except (ValueError, OSError) as exc:
                result.errors.append(f"Failed to extract {archive_path}: {exc}")
                result.finished_at = _now()
                return result

            # Scan the extracted contents.
            local = LocalScanner(self.config, self.engine, show_progress=self.show_progress)
            sub = local.scan(tmp_dir)
            # Rewrite file paths to be relative to the archive name.
            for f in sub.findings:
                # Replace tmp_dir prefix with archive name.
                try:
                    rel = Path(f.file_path).relative_to(tmp_dir)
                    f.file_path = f"{archive_path}!/{rel}"
                except ValueError:
                    pass
            result.findings.extend(sub.findings)
            result.files_scanned += sub.files_scanned
            result.files_skipped += sub.files_skipped
            result.errors.extend(sub.errors)
        finally:
            # Securely delete the temp directory.
            secure_delete(tmp_dir)

        result.finished_at = _now()
        return result


def _now():
    from datetime import datetime

    return datetime.now(UTC)


__all__ = ["ArchiveScanner"]
