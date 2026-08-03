"""Tests for the utils module: file IO, ignore matcher, safe extraction."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from secret_scanner.utils.fileio import (
    is_archive,
    is_binary_file,
    is_text_extension,
    safe_extract_zip,
    secure_delete,
)
from secret_scanner.utils.ignore import IgnoreMatcher


class TestBinaryDetection:
    def test_text_extension(self, tmp_path: Path) -> None:
        f = tmp_path / "x.py"
        f.write_text("print('hello')\n")
        assert not is_binary_file(f)

    def test_binary_extension(self, tmp_path: Path) -> None:
        f = tmp_path / "x.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\x00")
        assert is_binary_file(f)

    def test_no_extension_text(self, tmp_path: Path) -> None:
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.11\n")
        assert not is_binary_file(f)

    def test_no_extension_binary(self, tmp_path: Path) -> None:
        f = tmp_path / "binary"
        f.write_bytes(b"\x7fELF\x00\x00\x00\x00")
        assert is_binary_file(f)

    def test_utf8_with_bom(self, tmp_path: Path) -> None:
        f = tmp_path / "x.txt"
        f.write_bytes(b"\xef\xbb\xbfhello world\n")
        assert not is_binary_file(f)


class TestArchiveDetection:
    def test_zip(self) -> None:
        assert is_archive(Path("x.zip"))

    def test_jar(self) -> None:
        assert is_archive(Path("app.jar"))

    def test_tar_gz(self) -> None:
        assert is_archive(Path("x.tar.gz"))
        assert is_archive(Path("x.tgz"))

    def test_not_archive(self) -> None:
        assert not is_archive(Path("x.py"))
        assert not is_archive(Path("x.txt"))


class TestTextExtension:
    def test_python(self) -> None:
        assert is_text_extension(Path("app.py"))

    def test_yaml(self) -> None:
        assert is_text_extension(Path("conf.yaml"))

    def test_dockerfile(self) -> None:
        assert is_text_extension(Path("Dockerfile"))

    def test_env(self) -> None:
        assert is_text_extension(Path(".env"))

    def test_binary(self) -> None:
        assert not is_text_extension(Path("x.png"))


class TestSafeExtractZip:
    def test_normal_extraction(self, tmp_path: Path) -> None:
        # Build a benign zip.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("a.txt", "hello")
            zf.writestr("sub/b.txt", "world")
        zip_path = tmp_path / "x.zip"
        zip_path.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()
        safe_extract_zip(zip_path, dest)
        assert (dest / "a.txt").read_text() == "hello"
        assert (dest / "sub" / "b.txt").read_text() == "world"

    def test_rejects_absolute_path(self, tmp_path: Path) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("/etc/passwd", "evil")
        zip_path = tmp_path / "evil.zip"
        zip_path.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()
        try:
            safe_extract_zip(zip_path, dest)
            raise AssertionError("Should have refused")
        except ValueError:
            pass

    def test_rejects_traversal(self, tmp_path: Path) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../etc/evil", "evil")
        zip_path = tmp_path / "evil.zip"
        zip_path.write_bytes(buf.getvalue())
        dest = tmp_path / "out"
        dest.mkdir()
        try:
            safe_extract_zip(zip_path, dest)
            raise AssertionError("Should have refused")
        except ValueError:
            pass


class TestSecureDelete:
    def test_delete_file(self, tmp_path: Path) -> None:
        f = tmp_path / "secret.txt"
        f.write_text("supersecret")
        secure_delete(f)
        assert not f.exists()

    def test_delete_directory(self, tmp_path: Path) -> None:
        d = tmp_path / "subdir"
        d.mkdir()
        (d / "a.txt").write_text("a")
        (d / "b.txt").write_text("b")
        secure_delete(d)
        assert not d.exists()

    def test_delete_nonexistent_silent(self, tmp_path: Path) -> None:
        # Should not raise.
        secure_delete(tmp_path / "nope.txt")


class TestIgnoreMatcher:
    def test_default_ignores(self, tmp_path: Path) -> None:
        m = IgnoreMatcher(base_dir=tmp_path)
        assert m.is_ignored(tmp_path / "node_modules" / "x.js")
        assert m.is_ignored(tmp_path / ".git" / "config")
        assert m.is_ignored(tmp_path / "__pycache__" / "x.pyc")
        assert not m.is_ignored(tmp_path / "main.py")

    def test_secretignore(self, tmp_path: Path) -> None:
        (tmp_path / ".secretignore").write_text("secrets/**\n*.env\n")
        m = IgnoreMatcher(base_dir=tmp_path)
        assert m.is_ignored(tmp_path / "secrets" / "prod.env")
        assert m.is_ignored(tmp_path / "app.env")
        assert not m.is_ignored(tmp_path / "main.py")

    def test_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("*.log\ntmp/\n")
        m = IgnoreMatcher(base_dir=tmp_path)
        assert m.is_ignored(tmp_path / "app.log")
        assert m.is_ignored(tmp_path / "tmp" / "cache.txt")
        assert not m.is_ignored(tmp_path / "app.py")

    def test_custom_globs(self, tmp_path: Path) -> None:
        m = IgnoreMatcher(
            base_dir=tmp_path,
            glob_patterns=["*.bak", "vendor/"],
        )
        assert m.is_ignored(tmp_path / "config.bak")
        assert m.is_ignored(tmp_path / "vendor" / "lib.py")

    def test_custom_regex(self, tmp_path: Path) -> None:
        m = IgnoreMatcher(
            base_dir=tmp_path,
            regex_patterns=[r"^test/fixtures/.+$"],
        )
        assert m.is_ignored(tmp_path / "test" / "fixtures" / "sample.env")
        assert not m.is_ignored(tmp_path / "src" / "app.py")

    def test_disable_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("*.log\n")
        m = IgnoreMatcher(base_dir=tmp_path, use_gitignore=False)
        assert not m.is_ignored(tmp_path / "app.log")
