"""Tests for the config system."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from secret_scanner.config import ScanConfig, find_config


class TestScanConfig:
    def test_defaults(self) -> None:
        cfg = ScanConfig()
        assert cfg.min_entropy > 0
        assert cfg.workers >= 1
        assert cfg.max_file_size_mb > 0
        assert cfg.fail_on_severity == "low"

    def test_from_dict(self) -> None:
        data = {
            "min_entropy": 4.0,
            "min_length": 16,
            "max_file_size_mb": 10,
            "workers": 8,
            "enable_entropy": False,
            "ignore": ["*.bak"],
            "ignore_regex": ["^vendor/.+$"],
        }
        cfg = ScanConfig.from_dict(data)
        assert cfg.min_entropy == 4.0
        assert cfg.min_length == 16
        assert cfg.max_file_size_mb == 10
        assert cfg.workers == 8
        assert cfg.enable_entropy is False
        assert "*.bak" in cfg.ignore_globs
        assert "^vendor/.+$" in cfg.ignore_regexes

    def test_from_file(self, tmp_path: Path) -> None:
        yaml_content = dedent("""
        min_entropy: 4.2
        workers: 16
        ignore:
          - "*.bak"
          - "vendor/"
        fail_on_severity: high
        """)
        p = tmp_path / "secret-scanner.yaml"
        p.write_text(yaml_content)
        cfg = ScanConfig.from_file(p)
        assert cfg.min_entropy == 4.2
        assert cfg.workers == 16
        assert cfg.fail_on_severity == "high"
        assert "vendor/" in cfg.ignore_globs

    def test_from_file_missing(self, tmp_path: Path) -> None:
        try:
            ScanConfig.from_file(tmp_path / "nope.yaml")
            raise AssertionError()
        except FileNotFoundError:
            pass


class TestFindConfig:
    def test_finds_in_current_dir(self, tmp_path: Path) -> None:
        (tmp_path / "secret-scanner.yaml").write_text("workers: 4\n")
        assert find_config(tmp_path) is not None

    def test_finds_dotfile(self, tmp_path: Path) -> None:
        (tmp_path / ".secret-scanner.yaml").write_text("workers: 4\n")
        assert find_config(tmp_path) is not None

    def test_finds_in_parent(self, tmp_path: Path) -> None:
        (tmp_path / "secret-scanner.yaml").write_text("workers: 4\n")
        sub = tmp_path / "sub" / "deep"
        sub.mkdir(parents=True)
        found = find_config(sub)
        assert found is not None
        assert found.parent == tmp_path

    def test_returns_none_when_not_found(self, tmp_path: Path) -> None:
        assert find_config(tmp_path) is None


class TestSeverityOverrides:
    def test_apply_overrides(self, tmp_path: Path) -> None:
        from secret_scanner.config import ScanConfig
        from secret_scanner.models import Severity

        # Create a custom rule file.
        rules_yaml = dedent("""
        rules:
          - id: custom:test
            name: Test
            provider: custom
            pattern: 'CUSTOM[A-Z]{8}'
            severity: low
        """)
        rp = tmp_path / "rules.yaml"
        rp.write_text(rules_yaml)

        cfg = ScanConfig(custom_rule_files=[rp])
        cfg.severity_overrides = {"custom:test": "critical"}
        cfg.apply_overrides()
        rule = cfg.ruleset.get("custom:test")
        assert rule is not None
        assert rule.severity is Severity.CRITICAL
