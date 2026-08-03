"""Tests for the CLI commands.

All test secrets use ``SAMPLES`` (runtime-constructed) so that no literal
real-format secret pattern appears in the source file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from typer.testing import CliRunner

from secret_scanner.cli.main import app

from .samples import SAMPLES

runner = CliRunner()


class TestCLI:
    def test_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "secret-scanner" in result.stdout

    def test_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.stdout
        assert "github" in result.stdout

    def test_scan_command(self, tmp_path: Path) -> None:
        # Create a file with a secret.
        (tmp_path / "config.py").write_text(f'KEY = "{SAMPLES["aws_access_key_id"]}"\n')
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--format", "json", "--fail-on", "critical"]
        )
        assert result.exit_code in (0, 4)  # 4 if critical findings

    def test_scan_command_quiet(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text(f'KEY = "{SAMPLES["aws_access_key_id"]}"\n')
        result = runner.invoke(app, ["scan", str(tmp_path), "--quiet", "--fail-on", "low"])
        assert result.exit_code == 4  # critical finding

    def test_scan_clean_dir(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "low"])
        assert result.exit_code == 0

    def test_scan_json_output_to_file(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text(f'KEY = "{SAMPLES["aws_access_key_id"]}"\n')
        out = tmp_path / "report.json"
        runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--format",
                "json",
                "--output",
                str(out),
                "--fail-on",
                "critical",
            ],
        )
        assert out.is_file()
        data = json.loads(out.read_text())
        assert data["target"] == str(tmp_path)

    def test_scan_html_output_to_file(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text(f'KEY = "{SAMPLES["aws_access_key_id"]}"\n')
        out = tmp_path / "report.html"
        runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--format",
                "html",
                "--output",
                str(out),
                "--fail-on",
                "critical",
            ],
        )
        assert out.is_file()
        assert "<!DOCTYPE html>" in out.read_text()

    def test_scan_csv_output_to_file(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text(f'KEY = "{SAMPLES["aws_access_key_id"]}"\n')
        out = tmp_path / "report.csv"
        runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--format",
                "csv",
                "--output",
                str(out),
                "--fail-on",
                "critical",
            ],
        )
        assert out.is_file()
        assert "rule_id" in out.read_text()

    def test_scan_sarif_output_to_file(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text(f'KEY = "{SAMPLES["aws_access_key_id"]}"\n')
        out = tmp_path / "report.sarif"
        runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--format",
                "sarif",
                "--output",
                str(out),
                "--fail-on",
                "critical",
            ],
        )
        assert out.is_file()
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"

    def test_scan_markdown_output_to_file(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text(f'KEY = "{SAMPLES["aws_access_key_id"]}"\n')
        out = tmp_path / "report.md"
        runner.invoke(
            app,
            [
                "scan",
                str(tmp_path),
                "--format",
                "markdown",
                "--output",
                str(out),
                "--fail-on",
                "critical",
            ],
        )
        assert out.is_file()
        assert "# Secret Scanner Report" in out.read_text()

    def test_rules_command(self) -> None:
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0
        assert "Detection Rules" in result.stdout

    def test_rules_command_json(self) -> None:
        result = runner.invoke(app, ["rules", "--format", "json"])
        assert result.exit_code == 0

    def test_rules_command_filter_provider(self) -> None:
        result = runner.invoke(app, ["rules", "--provider", "aws_access_key"])
        assert result.exit_code == 0

    def test_scan_nonexistent_path(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["scan", str(tmp_path / "nope")])
        # Should not crash.
        assert result.exit_code == 0

    def test_baseline_command(self, tmp_path: Path) -> None:
        (tmp_path / "config.py").write_text(f'KEY = "{SAMPLES["aws_access_key_id"]}"\n')
        # Use a custom HOME so the cache goes to tmp_path.
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        env = {**os.environ, "HOME": str(tmp_path)}
        result = runner.invoke(app, ["baseline", str(tmp_path)], env=env)
        assert result.exit_code == 0
        assert "Baseline" in result.stdout
