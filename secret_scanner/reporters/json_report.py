"""JSON reporter (deterministic, machine-readable)."""

from __future__ import annotations

import orjson

from .base import Reporter


class JSONReporter(Reporter):
    """Render scan results as JSON."""

    def render(self, result) -> str:  # noqa: ANN001
        data = {
            "scanner_version": result.scanner_version,
            "target": result.target,
            "scan_type": result.scan_type,
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "finished_at": result.finished_at.isoformat() if result.finished_at else None,
            "duration_seconds": result.duration_seconds,
            "stats": {
                "files_scanned": result.files_scanned,
                "files_skipped": result.files_skipped,
                "bytes_scanned": result.bytes_scanned,
                "findings": result.finding_count,
                "unique_secrets": result.unique_secrets,
                "risk_score": result.risk_score(),
                "severity_counts": result.severity_counts(),
            },
            "findings": [self._finding_to_dict(f) for f in result.findings],
            "errors": result.errors,
        }
        # Use orjson for speed and native datetime handling.
        return orjson.dumps(data, option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS).decode("utf-8")

    @staticmethod
    def _finding_to_dict(f) -> dict:  # noqa: ANN001
        return {
            "rule_id": f.rule_id,
            "rule_name": f.rule_name,
            "provider": f.provider,
            "severity": f.severity.label,
            "confidence": f.confidence,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "column_start": f.column_start,
            "column_end": f.column_end,
            "masked_value": f.masked_value,
            "context_line": f.context_line,
            "detected_by": f.detected_by,
            "entropy": round(f.entropy, 4),
            "commit_sha": f.commit_sha,
            "commit_author": f.commit_author,
            "commit_date": f.commit_date.isoformat() if f.commit_date else None,
            "explanation": f.explanation,
            "recommendation": f.recommendation,
            "fingerprint": f.fingerprint,
        }


__all__ = ["JSONReporter"]
