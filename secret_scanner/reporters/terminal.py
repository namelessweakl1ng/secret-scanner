"""Rich terminal reporter: tables, severity colors, summary panel."""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import Severity
from .base import Reporter


class TerminalReporter(Reporter):
    """Render scan results as a polished Rich console output."""

    def __init__(self, *, console: Console | None = None, max_findings: int = 200) -> None:
        self.console = console or Console()
        self.max_findings = max_findings

    def render(self, result) -> str:  # noqa: ANN001
        """Render returns the same output as print, but as a string."""
        from io import StringIO

        string_console = Console(file=StringIO(), width=self.console.width, force_terminal=False)
        self._render(result, string_console)
        return string_console.file.getvalue()

    def print(self, result) -> None:  # noqa: ANN001
        self._render(result, self.console)

    def _render(self, result, console: Console) -> None:  # noqa: ANN001
        # Header.
        console.print()
        console.rule(f"[bold cyan]Secret Scanner — {result.scan_type.upper()}[/bold cyan]")
        console.print()

        # Summary panel.
        counts = result.severity_counts()
        risk = result.risk_score()
        risk_color = "red" if risk >= 50 else "yellow" if risk >= 25 else "green"
        summary_lines = [
            f"[bold]Target:[/bold] {result.target}",
            f"[bold]Files scanned:[/bold] {result.files_scanned}",
            f"[bold]Files skipped:[/bold] {result.files_skipped}",
            f"[bold]Findings:[/bold] {result.finding_count} ({result.unique_secrets} unique)",
            f"[bold]Risk score:[/bold] [{risk_color}]{risk}/100[/{risk_color}]",
            "",
            "[bold]Severity breakdown:[/bold]",
            f"  [bold red]Critical[/bold red]: {counts['Critical']}",
            f"  [red]High[/red]: {counts['High']}",
            f"  [yellow]Medium[/yellow]: {counts['Medium']}",
            f"  [cyan]Low[/cyan]: {counts['Low']}",
            f"  [dim]Info[/dim]: {counts['Info']}",
        ]
        console.print(Panel("\n".join(summary_lines), title="Scan Summary", border_style="cyan"))

        if result.errors:
            console.print()
            err_panel = Panel(
                "\n".join(f"[red]- {e}[/red]" for e in result.errors[:20]),
                title=f"Errors ({len(result.errors)})",
                border_style="red",
            )
            console.print(err_panel)

        if not result.findings:
            console.print()
            console.print(
                Panel("[green]No secrets found.[/green]", title="Result", border_style="green")
            )
            return

        # Findings table.
        console.print()
        table = Table(
            title=f"Findings ({min(len(result.findings), self.max_findings)} of {len(result.findings)} shown)",
            show_lines=True,
            border_style="bright_black",
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=28)
        table.add_column("File", overflow="fold")
        table.add_column("Line", justify="right", width=5)
        table.add_column("Conf.", justify="right", width=6)
        table.add_column("Value", overflow="fold")

        # Sort by severity desc, then confidence desc.
        sorted_findings = sorted(
            result.findings,
            key=lambda f: (-f.severity.value, -f.confidence),
        )
        for i, f in enumerate(sorted_findings[: self.max_findings], start=1):
            sev = f.severity
            table.add_row(
                str(i),
                Text(sev.label, style=sev.rich_style),
                f.rule_name,
                f.file_path,
                str(f.line_number),
                f"{f.confidence}%",
                f.masked_value,
            )
        console.print(table)

        # Top providers.
        if result.findings:
            console.print()
            providers = Counter(f.provider for f in result.findings)
            prov_table = Table(title="Top providers", show_header=True, border_style="bright_black")
            prov_table.add_column("Provider", style="cyan")
            prov_table.add_column("Count", justify="right", style="bold")
            for prov, count in providers.most_common(10):
                prov_table.add_row(prov, str(count))
            console.print(prov_table)

        # Recommendations panel.
        if sorted_findings:
            console.print()
            critical = [f for f in sorted_findings if f.severity == Severity.CRITICAL]
            if critical:
                rec = "[bold red]CRITICAL:[/bold red] Rotate the following immediately:\n"
                rec += "\n".join(
                    f"  • {f.rule_name} in [bold]{f.file_path}:{f.line_number}[/bold]"
                    for f in critical[:10]
                )
                console.print(Panel(rec, title="Recommendations", border_style="red"))

        console.print()


__all__ = ["TerminalReporter"]
