"""Base reporter interface."""

from __future__ import annotations

import abc
from pathlib import Path

from ..models import ScanResult


class Reporter(abc.ABC):
    """Abstract base class for all reporters."""

    @abc.abstractmethod
    def render(self, result: ScanResult) -> str:
        """Render the scan result to a string."""
        ...

    def render_to_file(self, result: ScanResult, path: str | Path) -> None:
        """Render the scan result and write it to ``path``."""
        Path(path).write_text(self.render(result), encoding="utf-8")

    def print(self, result: ScanResult) -> None:
        """Print the result to stdout (terminal reporters override this)."""
        print(self.render(result))


__all__ = ["Reporter"]
