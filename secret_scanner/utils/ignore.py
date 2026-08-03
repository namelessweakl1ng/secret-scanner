"""Path ignore system, compatible with .gitignore and .secretignore syntax."""

from __future__ import annotations

import contextlib
import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

import pathspec

# Default patterns that are always ignored (binary/irrelevant dirs).
DEFAULT_IGNORE_DIRS: tuple[str, ...] = (
    ".git/",
    ".hg/",
    ".svn/",
    "node_modules/",
    "__pycache__/",
    ".venv/",
    "venv/",
    "env/",
    ".env/",  # exclude the dir, but we still scan .env files inside
    ".tox/",
    ".mypy_cache/",
    ".pytest_cache/",
    ".ruff_cache/",
    ".cache/",
    "dist/",
    "build/",
    "target/",
    ".next/",
    ".nuxt/",
    ".gradle/",
    ".idea/",
    ".vscode/",
    "vendor/",
    ".terraform/",
    "*.egg-info/",
)


@dataclass
class IgnoreMatcher:
    """Composite ignore matcher.

    Combines:
    - Built-in default directory ignores
    - ``.gitignore`` patterns (optional, on by default)
    - ``.secretignore`` patterns (always on if present)
    - Custom glob patterns from config
    - Custom regex patterns from config
    """

    base_dir: Path
    use_gitignore: bool = True
    glob_patterns: list[str] = field(default_factory=list)
    regex_patterns: list[re.Pattern[str]] = field(default_factory=list)
    _gitignore_spec: pathspec.PathSpec | None = None
    _secretignore_spec: pathspec.PathSpec | None = None
    _custom_spec: pathspec.PathSpec | None = None

    def __post_init__(self) -> None:
        # Build the default spec.
        default_lines = list(DEFAULT_IGNORE_DIRS)
        self._default_spec = pathspec.PathSpec.from_lines("gitwildmatch", default_lines)

        # Load .gitignore (recursively, like git does).
        if self.use_gitignore:
            self._gitignore_spec = self._load_gitignore(self.base_dir)
        else:
            self._gitignore_spec = None

        # Load .secretignore.
        secretignore = self.base_dir / ".secretignore"
        if secretignore.is_file():
            try:
                lines = secretignore.read_text(encoding="utf-8").splitlines()
                self._secretignore_spec = pathspec.PathSpec.from_lines("gitwildmatch", lines)
            except OSError:
                self._secretignore_spec = None
        else:
            self._secretignore_spec = None

        # Custom globs from config.
        if self.glob_patterns:
            self._custom_spec = pathspec.PathSpec.from_lines("gitwildmatch", self.glob_patterns)
        else:
            self._custom_spec = None

        # Regex patterns compiled.
        self._compiled_regexes = [re.compile(p) for p in (self.regex_patterns or [])]

    @staticmethod
    def _load_gitignore(base: Path) -> pathspec.PathSpec:
        """Load all .gitignore files from base downward (shallow)."""
        lines: list[str] = []
        gitignore = base / ".gitignore"
        if gitignore.is_file():
            with contextlib.suppress(OSError):
                lines.extend(gitignore.read_text(encoding="utf-8").splitlines())
        return pathspec.PathSpec.from_lines("gitwildmatch", lines)

    def is_ignored(self, path: Path) -> bool:
        """Return True if a path should be ignored."""
        try:
            rel = path.resolve().relative_to(self.base_dir.resolve())
        except ValueError:
            # Path is outside base; ignore it (safety).
            return True
        rel_str = rel.as_posix()
        if not rel_str or rel_str == ".":
            return False

        # For directories, also try matching with trailing slash so that
        # patterns like "node_modules/" match. For files, only match without.
        is_dir = path.is_dir()
        candidates = [rel_str + "/"] if is_dir else []
        candidates.append(rel_str)

        # Default dir ignores.
        if any(self._default_spec.match_file(c) for c in candidates):
            return True

        # Custom glob spec.
        if self._custom_spec and any(self._custom_spec.match_file(c) for c in candidates):
            return True

        # .secretignore.
        if self._secretignore_spec and any(
            self._secretignore_spec.match_file(c) for c in candidates
        ):
            return True

        # .gitignore.
        if self._gitignore_spec and any(self._gitignore_spec.match_file(c) for c in candidates):
            return True

        # Custom regex.
        return any(rx.search(rel_str) for rx in self._compiled_regexes)


def match_glob(pattern: str, path: str) -> bool:
    """Simple glob match helper."""
    return fnmatch.fnmatch(path, pattern)


__all__ = ["IgnoreMatcher", "DEFAULT_IGNORE_DIRS", "match_glob"]
