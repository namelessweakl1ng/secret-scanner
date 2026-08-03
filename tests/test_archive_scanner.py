"""Tests for the archive scanner.

All test secrets use ``SAMPLES`` (runtime-constructed) so that no literal
real-format secret pattern appears in the source file.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

from secret_scanner.config import ScanConfig
from secret_scanner.detectors import Engine
from secret_scanner.scanners import ArchiveScanner

from .samples import SAMPLES


def make_scanner() -> ArchiveScanner:
    cfg = ScanConfig()
    cfg.apply_overrides()
    eng = Engine(cfg.ruleset, min_entropy=cfg.min_entropy, min_length=cfg.min_length)
    return ArchiveScanner(cfg, eng, show_progress=False)


class TestArchiveScanner:
    def test_scan_zip(self, tmp_path: Path) -> None:
        # Build a zip containing a file with a secret.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("config.py", f'KEY = "{SAMPLES["aws_access_key_id"]}"\n')
        zip_path = tmp_path / "x.zip"
        zip_path.write_bytes(buf.getvalue())

        s = make_scanner()
        result = s.scan_archive_file(zip_path)
        assert result.finding_count >= 1
        # File path should include the archive name.
        assert any("x.zip" in f.file_path for f in result.findings)

    def test_scan_tar(self, tmp_path: Path) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = f'GITHUB = "{SAMPLES["github_pat"]}"\n'.encode()
            info = tarfile.TarInfo(name="config.py")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        tar_path = tmp_path / "x.tar.gz"
        tar_path.write_bytes(buf.getvalue())

        s = make_scanner()
        result = s.scan_archive_file(tar_path)
        assert result.finding_count >= 1
        assert any("github" in f.rule_id for f in result.findings)

    def test_unsupported_type(self, tmp_path: Path) -> None:
        # Create a file with an unsupported extension.
        p = tmp_path / "x.xyz"
        p.write_text("hello")
        s = make_scanner()
        result = s.scan_archive_file(p)
        assert len(result.errors) >= 1

    def test_safe_extraction_failure(self, tmp_path: Path) -> None:
        # Build a malicious zip with traversal.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../etc/evil", "evil")
        zip_path = tmp_path / "evil.zip"
        zip_path.write_bytes(buf.getvalue())

        s = make_scanner()
        result = s.scan_archive_file(zip_path)
        # Should have an error, not a crash.
        assert len(result.errors) >= 1
        # Temp dir should be cleaned up.
        # (We can't directly assert this since we don't know the temp path,
        # but the scan should complete without leaving files behind.)

    def test_scans_nested_files(self, tmp_path: Path) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("nested/deep/config.py", f'AWS = "{SAMPLES["aws_access_key_id"]}"\n')
            zf.writestr("nested/deep/app.py", "print('hello')\n")
        zip_path = tmp_path / "nested.zip"
        zip_path.write_bytes(buf.getvalue())

        s = make_scanner()
        result = s.scan_archive_file(zip_path)
        assert result.finding_count >= 1
