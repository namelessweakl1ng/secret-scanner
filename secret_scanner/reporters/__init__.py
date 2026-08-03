"""Reporters: render ScanResults to terminal, JSON, CSV, Markdown, HTML, SARIF."""

from __future__ import annotations

from .base import Reporter
from .csv_report import CSVReporter
from .html import HTMLReporter
from .json_report import JSONReporter
from .markdown import MarkdownReporter
from .sarif import SARIFReporter
from .terminal import TerminalReporter

FORMAT_MAP: dict[str, type[Reporter]] = {
    "terminal": TerminalReporter,
    "json": JSONReporter,
    "csv": CSVReporter,
    "markdown": MarkdownReporter,
    "md": MarkdownReporter,
    "html": HTMLReporter,
    "sarif": SARIFReporter,
}


def get_reporter(fmt: str) -> Reporter:
    """Return a reporter instance for the given format name."""
    fmt = fmt.lower().strip()
    if fmt not in FORMAT_MAP:
        raise ValueError(f"Unknown format: {fmt}. Available: {', '.join(FORMAT_MAP)}")
    return FORMAT_MAP[fmt]()


__all__ = [
    "Reporter",
    "TerminalReporter",
    "JSONReporter",
    "CSVReporter",
    "MarkdownReporter",
    "HTMLReporter",
    "SARIFReporter",
    "FORMAT_MAP",
    "get_reporter",
]
