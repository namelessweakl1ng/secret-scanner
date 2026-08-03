"""Main Typer CLI for Secret Scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .. import __version__
from ..cache import Cache
from ..config import ScanConfig, find_config
from ..detectors import Engine
from ..models import Severity
from ..reporters import get_reporter
from ..reporters.terminal import TerminalReporter
from ..scanners import (
    ArchiveScanner,
    BitbucketScanner,
    GistScanner,
    GitHubScanner,
    GitLabScanner,
    GitScanner,
    LocalScanner,
    RawURLScanner,
)

app = typer.Typer(
    name="secret-scanner",
    help="Production-grade secret scanner: detect leaked credentials, API keys, tokens, and private keys.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    pretty_exceptions_show_locals=False,
)

console = Console()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_config(config_path: Path | None) -> ScanConfig:
    """Load config from explicit path or auto-discover."""
    if config_path:
        return ScanConfig.from_file(config_path)
    found = find_config(Path.cwd())
    if found:
        return ScanConfig.from_file(found)
    return ScanConfig()


def _make_engine(config: ScanConfig) -> Engine:
    return Engine(
        config.ruleset,
        min_entropy=config.min_entropy,
        min_length=config.min_length,
        max_length=config.max_length,
        max_line_length=config.max_line_length,
        enable_entropy=config.enable_entropy,
        enable_context=config.enable_context,
        enable_path_rules=config.enable_path_rules,
    )


def _output_result(
    result, fmt: str, output: Path | None, *, quiet: bool = False
) -> None:  # noqa: ANN001
    """Render result in the requested format and write to file or stdout."""
    if fmt == "terminal":
        if not quiet:
            TerminalReporter().print(result)
    else:
        reporter = get_reporter(fmt)
        content = reporter.render(result)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8")
            console.print(f"\n[green]✓[/green] Report written to [bold]{output}[/bold]")
        else:
            console.print(content)


def _exit_code_for(result, fail_on: str | None) -> int:  # noqa: ANN001
    """Compute exit code based on findings and fail-on threshold."""
    if not result.findings or fail_on is None:
        return 0
    threshold = Severity.parse(fail_on)
    dominant = result.dominant_severity
    if dominant >= threshold:
        # Return the dominant severity value (1-4).
        return int(dominant.value)
    return 0


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="File or directory to scan.")],
    format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: terminal|json|csv|markdown|html|sarif"),
    ] = "terminal",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write report to file.")
    ] = None,
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Path to secret-scanner.yaml.")
    ] = None,
    workers: Annotated[int, typer.Option("--workers", "-w", help="Parallel worker threads.")] = 4,
    max_size: Annotated[int, typer.Option("--max-size-mb", help="Max file size in MB.")] = 20,
    no_entropy: Annotated[
        bool, typer.Option("--no-entropy", help="Disable entropy detection.")
    ] = False,
    no_context: Annotated[
        bool, typer.Option("--no-context", help="Disable context detection.")
    ] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress progress output.")] = False,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit non-zero if findings at this severity or higher: info|low|medium|high|critical",
        ),
    ] = "low",
    baseline: Annotated[
        bool, typer.Option("--baseline", help="Suppress findings already in the baseline.")
    ] = False,
    record: Annotated[
        bool, typer.Option("--record", help="Record this scan in local history.")
    ] = False,
) -> None:
    """Scan a local file or directory for secrets."""
    cfg = _load_config(config)
    cfg.workers = workers
    cfg.max_file_size_mb = max_size
    if no_entropy:
        cfg.enable_entropy = False
    if no_context:
        cfg.enable_context = False
    cfg.fail_on_severity = fail_on
    if baseline:
        cache = Cache()
        cfg.baseline_fingerprints = cache.load_baseline_fingerprints()
    cfg.apply_overrides()
    engine = _make_engine(cfg)

    scanner = LocalScanner(cfg, engine, show_progress=not quiet)
    result = scanner.scan(path)

    if record:
        Cache().record_scan(result)

    _output_result(result, format, output, quiet=quiet)
    code = _exit_code_for(result, fail_on)
    if code:
        raise typer.Exit(code=code)


@app.command()
def history(
    path: Annotated[Path, typer.Argument(help="Git repository to scan.")] = Path("."),
    format: Annotated[str, typer.Option("--format", "-f", help="Output format.")] = "terminal",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    no_branches: Annotated[bool, typer.Option("--no-branches", help="Skip branch refs.")] = False,
    no_stashes: Annotated[bool, typer.Option("--no-stashes", help="Skip stash refs.")] = False,
    tags: Annotated[bool, typer.Option("--tags", help="Also scan tags.")] = False,
    blame: Annotated[
        bool, typer.Option("--blame", help="Attribution via git blame (slow).")
    ] = False,
    commit_limit: Annotated[
        int | None, typer.Option("--commit-limit", help="Max commits per ref.")
    ] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
    fail_on: Annotated[str | None, typer.Option("--fail-on")] = "low",
) -> None:
    """Scan a git repository's full history (commits, branches, stashes)."""
    cfg = _load_config(config)
    cfg.fail_on_severity = fail_on
    cfg.apply_overrides()
    engine = _make_engine(cfg)

    scanner = GitScanner(
        cfg,
        engine,
        show_progress=not quiet,
        scan_branches=not no_branches,
        scan_stashes=not no_stashes,
        scan_tags=tags,
        scan_blame=blame,
        commit_limit=commit_limit,
    )
    result = scanner.scan(path)
    _output_result(result, format, output, quiet=quiet)
    code = _exit_code_for(result, fail_on)
    if code:
        raise typer.Exit(code=code)


@app.command()
def github(
    repo: Annotated[str, typer.Argument(help="owner/repo or GitHub URL.")],
    format: Annotated[str, typer.Option("--format", "-f")] = "terminal",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    shallow: Annotated[
        bool, typer.Option("--shallow", help="Shallow clone (faster, no history).")
    ] = False,
    no_history: Annotated[
        bool, typer.Option("--no-history", help="Only scan the working tree.")
    ] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
    fail_on: Annotated[str | None, typer.Option("--fail-on")] = "low",
) -> None:
    """Scan a GitHub repository (public or private via GITHUB_TOKEN)."""
    cfg = _load_config(config)
    cfg.fail_on_severity = fail_on
    cfg.apply_overrides()
    engine = _make_engine(cfg)
    depth = 1 if shallow else None
    scanner = GitHubScanner(cfg, engine, show_progress=not quiet)
    result = scanner.scan(repo, scan_history=not no_history, depth=depth)
    _output_result(result, format, output, quiet=quiet)
    code = _exit_code_for(result, fail_on)
    if code:
        raise typer.Exit(code=code)


@app.command()
def gitlab(
    repo: Annotated[str, typer.Argument(help="GitLab URL or namespace/repo.")],
    format: Annotated[str, typer.Option("--format", "-f")] = "terminal",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    shallow: Annotated[bool, typer.Option("--shallow")] = False,
    no_history: Annotated[bool, typer.Option("--no-history")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
    fail_on: Annotated[str | None, typer.Option("--fail-on")] = "low",
) -> None:
    """Scan a GitLab repository (public or private via GITLAB_TOKEN)."""
    cfg = _load_config(config)
    cfg.fail_on_severity = fail_on
    cfg.apply_overrides()
    engine = _make_engine(cfg)
    scanner = GitLabScanner(cfg, engine, show_progress=not quiet)
    result = scanner.scan(repo, scan_history=not no_history, depth=1 if shallow else None)
    _output_result(result, format, output, quiet=quiet)
    code = _exit_code_for(result, fail_on)
    if code:
        raise typer.Exit(code=code)


@app.command()
def bitbucket(
    repo: Annotated[str, typer.Argument(help="Bitbucket URL or owner/repo.")],
    format: Annotated[str, typer.Option("--format", "-f")] = "terminal",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    shallow: Annotated[bool, typer.Option("--shallow")] = False,
    no_history: Annotated[bool, typer.Option("--no-history")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
    fail_on: Annotated[str | None, typer.Option("--fail-on")] = "low",
) -> None:
    """Scan a Bitbucket repository."""
    cfg = _load_config(config)
    cfg.fail_on_severity = fail_on
    cfg.apply_overrides()
    engine = _make_engine(cfg)
    scanner = BitbucketScanner(cfg, engine, show_progress=not quiet)
    result = scanner.scan(repo, scan_history=not no_history, depth=1 if shallow else None)
    _output_result(result, format, output, quiet=quiet)
    code = _exit_code_for(result, fail_on)
    if code:
        raise typer.Exit(code=code)


@app.command()
def gist(
    gist: Annotated[str, typer.Argument(help="Gist URL or ID.")],
    format: Annotated[str, typer.Option("--format", "-f")] = "terminal",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
    fail_on: Annotated[str | None, typer.Option("--fail-on")] = "low",
) -> None:
    """Scan a GitHub gist."""
    cfg = _load_config(config)
    cfg.fail_on_severity = fail_on
    cfg.apply_overrides()
    engine = _make_engine(cfg)
    scanner = GistScanner(cfg, engine, show_progress=not quiet)
    result = scanner.scan(gist)
    _output_result(result, format, output, quiet=quiet)
    code = _exit_code_for(result, fail_on)
    if code:
        raise typer.Exit(code=code)


@app.command()
def archive(
    path: Annotated[Path, typer.Argument(help="Archive file (.zip, .tar, .gz, .jar, .apk, ...).")],
    format: Annotated[str, typer.Option("--format", "-f")] = "terminal",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
    fail_on: Annotated[str | None, typer.Option("--fail-on")] = "low",
) -> None:
    """Extract and scan an archive file (ZIP/TAR/JAR/APK/...)."""
    cfg = _load_config(config)
    cfg.fail_on_severity = fail_on
    cfg.apply_overrides()
    engine = _make_engine(cfg)
    scanner = ArchiveScanner(cfg, engine, show_progress=not quiet)
    result = scanner.scan_archive_file(path)
    _output_result(result, format, output, quiet=quiet)
    code = _exit_code_for(result, fail_on)
    if code:
        raise typer.Exit(code=code)


@app.command()
def url(
    target: Annotated[str, typer.Argument(help="Raw URL to download and scan.")],
    format: Annotated[str, typer.Option("--format", "-f")] = "terminal",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
    fail_on: Annotated[str | None, typer.Option("--fail-on")] = "low",
) -> None:
    """Download a file from a URL and scan it."""
    cfg = _load_config(config)
    cfg.fail_on_severity = fail_on
    cfg.apply_overrides()
    engine = _make_engine(cfg)
    scanner = RawURLScanner(cfg, engine)
    result = scanner.scan(target)
    _output_result(result, format, output, quiet=quiet)
    code = _exit_code_for(result, fail_on)
    if code:
        raise typer.Exit(code=code)


@app.command()
def audit(
    path: Annotated[Path, typer.Argument(help="Path to audit.")] = Path("."),
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    fail_on: Annotated[str | None, typer.Option("--fail-on")] = "low",
) -> None:
    """Audit a path: scan + history + produce an HTML dashboard."""
    cfg = _load_config(config)
    cfg.fail_on_severity = fail_on
    cfg.apply_overrides()
    engine = _make_engine(cfg)

    # Run both local and git history if applicable.
    from ..git import is_git_repo as _is_git

    local = LocalScanner(cfg, engine, show_progress=True)
    result = local.scan(path)

    if _is_git(path):
        git_scanner = GitScanner(cfg, engine, show_progress=True, commit_limit=500)
        git_result = git_scanner.scan(path)
        result.findings.extend(git_result.findings)
        result.files_scanned += git_result.files_scanned
        result.errors.extend(git_result.errors)

    # Deduplicate.
    seen: set[tuple[str, int, str]] = set()
    deduped = []
    for f in result.findings:
        key = (f.file_path, f.line_number, f.fingerprint)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    result.findings = deduped

    # Always write HTML dashboard.
    out = Path("secret-scanner-audit.html")
    _output_result(result, "html", out, quiet=False)
    code = _exit_code_for(result, fail_on)
    if code:
        raise typer.Exit(code=code)


@app.command()
def baseline(
    path: Annotated[Path, typer.Argument(help="Path to scan to establish the baseline.")] = Path(
        "."
    ),
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
) -> None:
    """Save current findings as the baseline. Future scans with --baseline suppress them."""
    cfg = _load_config(config)
    cfg.apply_overrides()
    engine = _make_engine(cfg)

    scanner = LocalScanner(cfg, engine, show_progress=True)
    result = scanner.scan(path)
    cache = Cache()
    count = cache.save_baseline(result)
    console.print(
        Panel(
            f"[green]✓[/green] Baseline saved with [bold]{count}[/bold] unique secret fingerprints.\n\n"
            "Future scans with [cyan]--baseline[/cyan] will suppress these findings and only report new leaks.",
            title="Baseline Saved",
            border_style="green",
        )
    )


@app.command("install-hooks")
def install_hooks(
    target: Annotated[Path, typer.Argument(help="Git repo to install hooks into.")] = Path("."),
    hook: Annotated[str, typer.Option("--hook", help="pre-commit | pre-push")] = "pre-commit",
) -> None:
    """Install a git hook that runs secret-scanner before commit/push."""
    from ..git import git_root, is_git_repo

    if not is_git_repo(target):
        console.print("[red]Not a git repository.[/red]")
        raise typer.Exit(1)

    root = git_root(target)
    hooks_dir = root / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_path = hooks_dir / hook
    content = f"""#!/usr/bin/env bash
# Installed by secret-scanner v{__version__}
set -e
exec secret-scanner scan . --fail-on high --quiet
"""
    hook_path.write_text(content, encoding="utf-8")
    hook_path.chmod(0o755)
    console.print(f"[green]✓[/green] Installed {hook} hook at [bold]{hook_path}[/bold]")


@app.command()
def rules(
    provider: Annotated[
        str | None, typer.Option("--provider", "-p", help="Filter by provider.")
    ] = None,
    tag: Annotated[str | None, typer.Option("--tag", "-t", help="Filter by tag.")] = None,
    format: Annotated[str, typer.Option("--format", "-f", help="terminal|json")] = "terminal",
) -> None:
    """List all built-in detection rules."""
    from ..rules import load_default_ruleset

    rs = load_default_ruleset()
    if provider:
        rs = rs.filter_by_provider(provider)
    if tag:
        rs = rs.filter_by_tag(tag)

    if format == "json":
        import orjson

        console.print_json(
            orjson.dumps([r.to_dict() for r in rs], option=orjson.OPT_INDENT_2).decode()
        )
        return

    table = Table(
        title=f"Detection Rules ({len(rs)})", show_lines=False, border_style="bright_black"
    )
    table.add_column("ID", style="cyan", overflow="fold")
    table.add_column("Name", overflow="fold")
    table.add_column("Provider", style="magenta")
    table.add_column("Severity", width=10)
    table.add_column("Pattern", overflow="fold", max_width=60)
    for r in rs:
        table.add_row(
            r.id,
            r.name,
            r.provider,
            r.severity.label,
            r.pattern[:80] + ("..." if len(r.pattern) > 80 else ""),
        )
    console.print(table)


@app.command()
def interactive() -> None:
    """Interactive menu-driven mode."""
    console.print(
        Panel.fit(
            f"[bold cyan]Secret Scanner v{__version__}[/bold cyan]\nInteractive Mode",
            border_style="cyan",
        )
    )
    while True:
        console.print()
        choice = Prompt.ask(
            "[bold]Choose an action[/bold]",
            choices=["1", "2", "3", "4", "5", "6", "q"],
            default="q",
        )
        if choice == "q":
            break
        if choice == "1":
            path = Prompt.ask("Path to scan", default=".")
            cfg = ScanConfig()
            cfg.apply_overrides()
            engine = _make_engine(cfg)
            scanner = LocalScanner(cfg, engine)
            result = scanner.scan(Path(path))
            TerminalReporter().print(result)
        elif choice == "2":
            repo = Prompt.ask("GitHub repo (owner/repo or URL)")
            cfg = ScanConfig()
            cfg.apply_overrides()
            engine = _make_engine(cfg)
            scanner = GitHubScanner(cfg, engine)
            result = scanner.scan(repo, scan_history=False)
            TerminalReporter().print(result)
        elif choice == "3":
            path = Prompt.ask("Git repo path", default=".")
            cfg = ScanConfig()
            cfg.apply_overrides()
            engine = _make_engine(cfg)
            scanner = GitScanner(cfg, engine)
            result = scanner.scan(Path(path))
            TerminalReporter().print(result)
        elif choice == "4":
            path = Prompt.ask("Path", default=".")
            cfg = ScanConfig()
            cfg.apply_overrides()
            engine = _make_engine(cfg)
            scanner = LocalScanner(cfg, engine)
            result = scanner.scan(Path(path))
            from ..reporters import HTMLReporter

            HTMLReporter().render_to_file(result, Path("secret-scanner-report.html"))
            console.print("[green]✓[/green] Report saved to secret-scanner-report.html")
        elif choice == "5":
            rs = load_default_ruleset_len()
            console.print(f"[cyan]{rs}[/cyan] rules loaded.")
        elif choice == "6":
            cache = Cache()
            scans = cache.list_scans()
            if not scans:
                console.print("[dim]No scan history yet.[/dim]")
            else:
                t = Table(title="Recent Scans", border_style="bright_black")
                t.add_column("ID")
                t.add_column("Target")
                t.add_column("Type")
                t.add_column("Findings", justify="right")
                t.add_column("Risk", justify="right")
                t.add_column("Date")
                for s in scans[:20]:
                    t.add_row(
                        str(s["id"]),
                        s["target"],
                        s["scan_type"],
                        str(s["findings_count"]),
                        str(s["risk_score"]),
                        s["started_at"][:19],
                    )
                console.print(t)


def load_default_ruleset_len() -> int:
    from ..rules import load_default_ruleset

    return len(load_default_ruleset())


@app.command()
def version() -> None:
    """Print version information."""
    console.print(f"secret-scanner v{__version__}")


@app.callback()
def main(
    ctx: typer.Context,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging.")
    ] = False,
    debug: Annotated[bool, typer.Option("--debug", help="Enable debug logging.")] = False,
) -> None:
    """Production-grade secret scanner."""
    if debug:
        import logging

        logging.basicConfig(
            level=logging.DEBUG, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
        )
    elif verbose:
        import logging

        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


if __name__ == "__main__":
    app()
