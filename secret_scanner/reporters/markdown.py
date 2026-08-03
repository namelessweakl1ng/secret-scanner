"""Markdown reporter."""

from __future__ import annotations

from .base import Reporter


class MarkdownReporter(Reporter):
    """Render findings as a Markdown report."""

    def render(self, result) -> str:  # noqa: ANN001
        lines: list[str] = []
        lines.append("# Secret Scanner Report")
        lines.append("")
        lines.append(f"- **Target:** `{result.target}`")
        lines.append(f"- **Scan type:** {result.scan_type}")
        lines.append(f"- **Files scanned:** {result.files_scanned}")
        lines.append(f"- **Files skipped:** {result.files_skipped}")
        lines.append(f"- **Findings:** {result.finding_count} ({result.unique_secrets} unique)")
        lines.append(f"- **Risk score:** {result.risk_score()}/100")
        lines.append("")

        counts = result.severity_counts()
        lines.append("## Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            lines.append(f"| {sev} | {counts[sev]} |")
        lines.append("")

        if result.errors:
            lines.append("## Errors")
            lines.append("")
            for err in result.errors[:50]:
                lines.append(f"- {err}")
            lines.append("")

        if not result.findings:
            lines.append("## ✅ No secrets found")
            lines.append("")
            return "\n".join(lines)

        sorted_findings = sorted(
            result.findings,
            key=lambda f: (-f.severity.value, -f.confidence),
        )

        lines.append("## Findings")
        lines.append("")
        lines.append("| # | Severity | Type | File | Line | Confidence | Value |")
        lines.append("|---|----------|------|------|------|------------|-------|")
        for i, f in enumerate(sorted_findings, start=1):
            lines.append(
                f"| {i} | {f.severity.label} | {f.rule_name} | "
                f"`{f.file_path}` | {f.line_number} | {f.confidence}% | `{f.masked_value}` |"
            )
        lines.append("")

        lines.append("## Recommendations")
        lines.append("")
        critical = [f for f in sorted_findings if f.severity.name == "CRITICAL"]
        if critical:
            lines.append("### Critical — rotate immediately")
            lines.append("")
            for f in critical:
                lines.append(
                    f"- **{f.rule_name}** in `{f.file_path}:{f.line_number}`: "
                    f"{f.recommendation}"
                )
            lines.append("")

        high = [f for f in sorted_findings if f.severity.name == "HIGH"]
        if high:
            lines.append("### High — investigate and rotate")
            lines.append("")
            for f in high[:20]:
                lines.append(f"- **{f.rule_name}** in `{f.file_path}:{f.line_number}`")
            lines.append("")

        return "\n".join(lines)


__all__ = ["MarkdownReporter"]
