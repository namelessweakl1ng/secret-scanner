"""CSV reporter."""

from __future__ import annotations

import csv
import io

from .base import Reporter


class CSVReporter(Reporter):
    """Render findings as CSV (one row per finding)."""

    HEADER: tuple[str, ...] = (
        "rule_id",
        "rule_name",
        "provider",
        "severity",
        "confidence",
        "file_path",
        "line_number",
        "column_start",
        "column_end",
        "masked_value",
        "detected_by",
        "entropy",
        "commit_sha",
        "commit_author",
        "recommendation",
        "fingerprint",
    )

    def render(self, result) -> str:  # noqa: ANN001
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(self.HEADER)
        for f in result.findings:
            writer.writerow(
                [
                    f.rule_id,
                    f.rule_name,
                    f.provider,
                    f.severity.label,
                    f.confidence,
                    f.file_path,
                    f.line_number,
                    f.column_start,
                    f.column_end,
                    f.masked_value,
                    f.detected_by,
                    round(f.entropy, 4),
                    f.commit_sha or "",
                    f.commit_author or "",
                    f.recommendation,
                    f.fingerprint,
                ]
            )
        return buf.getvalue()


__all__ = ["CSVReporter"]
