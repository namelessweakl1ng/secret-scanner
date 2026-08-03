"""Utility helpers: file IO, binary detection, path safety, secure deletion."""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import tempfile
from collections.abc import Iterable
from pathlib import Path

# Binary file signature detection (magic bytes).
_BINARY_SIGNATURES: tuple[bytes, ...] = (
    b"\x7fELF",  # ELF
    b"\x4d\x5a",  # PE / MZ
    b"\xca\xfe\xba\xbe",  # Java class
    b"\x50\x4b\x03\x04",  # ZIP / JAR / WAR / APK / XPI
    b"\x1f\x8b",  # GZIP
    b"\x42\x5a\x68",  # BZIP2
    b"\x37\x7a\xbc\xaf\x27\x1c",  # 7z
    b"\x52\x61\x72\x21\x1a\x07",  # RAR
    b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a",  # PNG
    b"\xff\xd8\xff",  # JPEG
    b"\x47\x49\x46\x38",  # GIF
    b"\x42\x4d",  # BMP
    b"\x25\x50\x44\x46",  # PDF
    b"\xd0\xcf\x11\xe0",  # OLE / MS Office
    b"\x00\x00\x01\x00",  # ICO
    b"\x00\x00\x02\x00",  # CUR
    b"\xfd\x37\x7a\x58\x5a\x00",  # XZ
    b"\x28\xb5\x2f\xfd",  # Zstandard
)

# Extensions that are always treated as binary.
_BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".cur",
        ".webp",
        ".tiff",
        ".tif",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".mkv",
        ".wav",
        ".flac",
        ".ogg",
        ".webm",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".zst",
        ".jar",
        ".war",
        ".ear",
        ".apk",
        ".ipa",
        ".xpi",
        ".crx",
        ".class",
        ".pyc",
        ".pyo",
        ".o",
        ".so",
        ".dll",
        ".dylib",
        ".exe",
        ".bin",
        ".wasm",
        ".dex",
        ".smali",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".sqlite",
        ".db",
        ".mdb",
        ".lock",
        ".sum",  # lockfiles are usually not interesting for secrets
    }
)

# Extensions that ARE scanned as text (everything else defaults to "guess by content").
_TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".mjs",
        ".cjs",
        ".java",
        ".kt",
        ".kts",
        ".scala",
        ".groovy",
        ".go",
        ".rs",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".cxx",
        ".hpp",
        ".hxx",
        ".cs",
        ".fs",
        ".vb",
        ".php",
        ".rb",
        ".swift",
        ".m",
        ".mm",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".bat",
        ".cmd",
        ".yml",
        ".yaml",
        ".toml",
        ".json",
        ".json5",
        ".jsonc",
        ".xml",
        ".html",
        ".htm",
        ".css",
        ".scss",
        ".sass",
        ".less",
        ".md",
        ".rst",
        ".txt",
        ".text",
        ".log",
        ".env",
        ".ini",
        ".cfg",
        ".conf",
        ".config",
        ".properties",
        ".sql",
        ".graphql",
        ".gql",
        ".proto",
        ".dockerfile",
        ".containerfile",
        ".tf",
        ".tfvars",
        ".hcl",
        ".tfstate",
        ".gitignore",
        ".gitattributes",
        ".dockerignore",
        ".editorconfig",
        ".csv",
        ".tsv",
        ".tex",
        ".bib",
        ".vue",
        ".svelte",
        ".astro",
        ".lua",
        ".r",
        ".jl",
        ".ex",
        ".exs",
        ".erl",
        ".clj",
        ".cljs",
        ".lisp",
        ".scm",
        ".pl",
        ".pm",
        ".vim",
        ".el",
        ".nix",
        ".dhall",
    }
)

# Files with these names (any extension) are scanned as text.
_TEXT_FILENAMES: frozenset[str] = frozenset(
    {
        "dockerfile",
        "containerfile",
        "makefile",
        "gnumakefile",
        "jenkinsfile",
        "jenkinsfile.groovy",
        "rakefile",
        "gemfile",
        "gemfile.lock",
        "podfile",
        "cartfile",
        "brewfile",
        "vagrantfile",
        "procfile",
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        ".env.staging",
        ".env.dev",
        ".env.prod",
        ".env.test",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".gitignore",
        ".gitattributes",
        ".dockerignore",
        ".editorconfig",
        "license",
        "licence",
        "copying",
        "readme",
        "changelog",
        "authors",
        "contributors",
        "todo",
        "notice",
        "cmakelists.txt",
    }
)

# Maximum line length to scan (longer = likely minified / data file).
_MAX_LINE_LENGTH = 100_000


def is_binary_file(path: Path, *, sniff_bytes: int = 2048) -> bool:
    """Return True if a file appears to be binary.

    Uses two signals:
    1. Known binary extension.
    2. NUL byte or invalid UTF-8 in the first ``sniff_bytes``.

    Archives (.zip, .jar, .apk, etc.) are detected as binary, but the caller
    can choose to recurse into them via the archive scanner.
    """
    ext = path.suffix.lower()
    if ext in _BINARY_EXTENSIONS:
        return True

    name = path.name.lower()
    if name in _TEXT_FILENAMES:
        return False
    if ext in _TEXT_EXTENSIONS:
        return False

    # Sniff the first bytes.
    try:
        with path.open("rb") as f:
            chunk = f.read(sniff_bytes)
    except OSError:
        return True

    if not chunk:
        return False
    if chunk.startswith(_BINARY_SIGNATURES):
        return True
    if b"\x00" in chunk:
        return True
    # Try to decode as UTF-8.
    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError:
        # Try latin-1 as a last resort for very loose text files.
        try:
            chunk.decode("latin-1")
        except UnicodeDecodeError:
            return True
    return False


def is_archive(path: Path) -> bool:
    """Return True if the path is a supported archive."""
    ext = path.suffix.lower()
    return ext in {
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
        ".7z",
        ".rar",
        ".zst",
    }


def is_text_extension(path: Path) -> bool:
    """Return True if the path has a text-like extension."""
    ext = path.suffix.lower()
    if ext in _TEXT_EXTENSIONS:
        return True
    return path.name.lower() in _TEXT_FILENAMES


def read_text_lines(path: Path, *, max_bytes: int | None = None) -> Iterable[str]:
    """Stream lines from a text file without loading it all into memory.

    Lines longer than :data:`_MAX_LINE_LENGTH` are skipped (likely minified
    or data blobs that don't contain secrets we can match meaningfully).
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            bytes_read = 0
            for line in f:
                if max_bytes is not None:
                    bytes_read += len(line.encode("utf-8", errors="replace"))
                    if bytes_read > max_bytes:
                        return
                if len(line) > _MAX_LINE_LENGTH:
                    continue
                yield line.rstrip("\n")
    except OSError:
        return


def safe_extract_zip(zip_path: Path, dest: Path) -> None:
    """Safely extract a ZIP archive, mitigating Zip Slip.

    Refuses to extract entries whose resolved path escapes ``dest``.
    Refuses to extract absolute paths.
    Refuses to extract entries with suspicious components (``..``).
    """
    import zipfile

    dest = dest.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            # Reject absolute paths and parent traversal.
            if info.filename.startswith(("/", "\\")):
                raise ValueError(f"Refusing absolute path in zip: {info.filename}")
            if ".." in Path(info.filename).parts:
                raise ValueError(f"Refusing traversal path in zip: {info.filename}")
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest)):
                raise ValueError(f"Zip Slip detected: {info.filename}")
            zf.extract(info, dest)


def safe_extract_tar(tar_path: Path, dest: Path) -> None:
    """Safely extract a TAR archive, mitigating path traversal."""
    import tarfile

    dest = dest.resolve()
    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf.getmembers():
            if member.name.startswith(("/", "\\")):
                raise ValueError(f"Refusing absolute path in tar: {member.name}")
            if ".." in Path(member.name).parts:
                raise ValueError(f"Refusing traversal path in tar: {member.name}")
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest)):
                raise ValueError(f"TAR Slip detected: {member.name}")
            # Refuse special device files / symlinks pointing outside dest.
            if member.issym() or member.islnk():
                raise ValueError(f"Refusing symlink in tar: {member.name}")
            if member.isdev():
                raise ValueError(f"Refusing device file in tar: {member.name}")
            # Use the 'data' filter if available (Python 3.12+) to apply
            # additional safety; fall back to no filter on older versions.
            try:
                tf.extract(member, dest, filter="data")
            except TypeError:
                tf.extract(member, dest)


def secure_delete(path: Path, *, passes: int = 1) -> None:
    """Securely delete a file or directory.

    For files: overwrite with zeros (single pass) then unlink. For
    directories: walk and securely delete each file, then remove dirs.
    Single pass is sufficient on modern SSDs and flash storage (multiple
    passes give a false sense of security on wear-leveling media).
    """
    path = Path(path)
    if not path.exists():
        return

    if path.is_dir():
        for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                secure_delete(Path(root) / name, passes=passes)
            for name in dirs:
                with contextlib.suppress(OSError):
                    (Path(root) / name).rmdir()
        with contextlib.suppress(OSError):
            path.rmdir()
            return
        shutil.rmtree(path, ignore_errors=True)
        return

    # File: overwrite then unlink.
    with contextlib.suppress(OSError):
        size = path.stat().st_size
        with path.open("r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
    with contextlib.suppress(OSError):
        path.unlink()


def make_temp_dir(prefix: str = "secret-scanner-") -> Path:
    """Create a temporary directory under the system temp location."""
    return Path(tempfile.mkdtemp(prefix=prefix))


def is_within(path: Path, base: Path) -> bool:
    """Return True if ``path`` is inside ``base`` (after symlink resolution)."""
    with contextlib.suppress(ValueError):
        path.resolve().relative_to(base.resolve())
        return True
    return False


def make_readonly(path: Path) -> None:
    """Make a file read-only (best effort)."""
    with contextlib.suppress(OSError):
        path.chmod(path.stat().st_mode & ~stat.S_IWRITE)


def sanitize_path_for_display(path: str) -> str:
    """Normalize a path for display (replace home dir with ~, etc.)."""
    home = str(Path.home())
    if path.startswith(home):
        return "~" + path[len(home) :]
    return path


__all__ = [
    "is_binary_file",
    "is_archive",
    "is_text_extension",
    "read_text_lines",
    "safe_extract_zip",
    "safe_extract_tar",
    "secure_delete",
    "make_temp_dir",
    "is_within",
    "make_readonly",
    "sanitize_path_for_display",
]
