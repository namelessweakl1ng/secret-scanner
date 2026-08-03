"""Tests for the local scanner.

All test secrets use ``SAMPLES`` (runtime-constructed) so that no literal
real-format secret pattern appears in the source file.
"""

from __future__ import annotations

from pathlib import Path

from secret_scanner.config import ScanConfig
from secret_scanner.detectors import Engine
from secret_scanner.models import Severity
from secret_scanner.scanners import LocalScanner

from .samples import SAMPLES


def make_scanner(**config_overrides) -> LocalScanner:  # noqa: ANN001
    cfg = ScanConfig()
    for k, v in config_overrides.items():
        setattr(cfg, k, v)
    cfg.apply_overrides()
    eng = Engine(
        cfg.ruleset,
        min_entropy=cfg.min_entropy,
        min_length=cfg.min_length,
        max_length=cfg.max_length,
        enable_entropy=cfg.enable_entropy,
        enable_context=cfg.enable_context,
        enable_path_rules=cfg.enable_path_rules,
    )
    return LocalScanner(cfg, eng, show_progress=False)


class TestLocalScanner:
    def test_scan_file(self, tmp_path: Path) -> None:
        f = tmp_path / "config.py"
        f.write_text(f'AWS_KEY = "{SAMPLES["aws_access_key_id"]}"\n')
        s = make_scanner()
        result = s.scan(f)
        assert result.finding_count >= 1
        assert any(f.rule_id == "aws_access_key_id" for f in result.findings)

    def test_scan_directory(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text(f'KEY = "{SAMPLES["github_pat"]}"\n')
        (tmp_path / "b.py").write_text(f'KEY = "{SAMPLES["stripe_secret"]}"\n')
        (tmp_path / "c.py").write_text("print('hello')\n")
        s = make_scanner()
        result = s.scan(tmp_path)
        assert result.finding_count >= 2

    def test_scan_empty_dir(self, tmp_path: Path) -> None:
        s = make_scanner()
        result = s.scan(tmp_path)
        assert result.finding_count == 0
        assert result.dominant_severity is Severity.INFO

    def test_scan_nonexistent_path(self, tmp_path: Path) -> None:
        s = make_scanner()
        result = s.scan(tmp_path / "nope")
        assert len(result.errors) >= 1

    def test_scan_skips_binary_files(self, tmp_path: Path) -> None:
        # Write a binary file containing what would otherwise be a match.
        (tmp_path / "image.png").write_bytes(
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 100 + SAMPLES["aws_access_key_id"].encode()
        )
        s = make_scanner()
        result = s.scan(tmp_path)
        # Binary files should be skipped, no findings.
        assert result.finding_count == 0
        assert result.files_skipped >= 1

    def test_scan_respects_secretignore(self, tmp_path: Path) -> None:
        (tmp_path / "secret.py").write_text(f'KEY = "{SAMPLES["github_pat"]}"\n')
        (tmp_path / ".secretignore").write_text("secret.py\n")
        s = make_scanner()
        result = s.scan(tmp_path)
        assert result.finding_count == 0

    def test_scan_respects_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / "ignored.py").write_text(f'KEY = "{SAMPLES["github_pat"]}"\n')
        (tmp_path / ".gitignore").write_text("ignored.py\n")
        s = make_scanner()
        result = s.scan(tmp_path)
        assert result.finding_count == 0

    def test_scan_finds_env_file_by_path(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("FOO=bar\n")
        s = make_scanner()
        result = s.scan(tmp_path)
        assert any(".env" in f.rule_name for f in result.findings)

    def test_scan_handles_unicode(self, tmp_path: Path) -> None:
        f = tmp_path / "unicode.py"
        f.write_text(
            f'# \u4e2d\u6587\u6ce8\u91ca\nAPI_KEY = "{SAMPLES["aws_access_key_id"]}"\n',
            encoding="utf-8",
        )
        s = make_scanner()
        result = s.scan(f)
        assert any(f.rule_id == "aws_access_key_id" for f in result.findings)

    def test_scan_max_file_size(self, tmp_path: Path) -> None:
        f = tmp_path / "large.py"
        f.write_text("x" * (5 * 1024 * 1024))  # 5MB
        s = make_scanner(max_file_size_mb=1)
        result = s.scan(f)
        assert result.finding_count == 0

    def test_scan_multiple_providers(self, tmp_path: Path) -> None:
        f = tmp_path / "config.py"
        f.write_text(
            f'AWS = "{SAMPLES["aws_access_key_id"]}"\n'
            f'GH = "{SAMPLES["github_pat"]}"\n'
            f'STRIPE = "{SAMPLES["stripe_secret"]}"\n'
            f'OPENAI = "{SAMPLES["openai_key_short"]}"\n'
        )
        s = make_scanner()
        result = s.scan(f)
        providers = {f.provider for f in result.findings}
        assert "aws_access_key" in providers
        assert "github_pat" in providers
        assert "stripe_secret_key" in providers

    def test_scan_with_baseline_suppression(self, tmp_path: Path) -> None:
        f = tmp_path / "config.py"
        f.write_text(f'KEY = "{SAMPLES["github_pat"]}"\n')
        s = make_scanner()
        result = s.scan(f)
        # Build a baseline from the findings.
        baseline = {f_.fingerprint for f_ in result.findings}
        # Re-scan with baseline.
        s2 = make_scanner()
        s2.config.baseline_fingerprints = baseline
        result2 = s2.scan(f)
        assert result2.finding_count == 0

    def test_deduplication(self, tmp_path: Path) -> None:
        # Same secret in multiple files - each gets its own finding but with
        # the same fingerprint.
        secret = SAMPLES["aws_access_key_id"]
        (tmp_path / "a.py").write_text(f'KEY = "{secret}"\n')
        (tmp_path / "b.py").write_text(f'KEY = "{secret}"\n')
        s = make_scanner()
        result = s.scan(tmp_path)
        # Two findings (one per file) but only 1 unique fingerprint.
        aws_findings = [f for f in result.findings if f.rule_id == "aws_access_key_id"]
        assert len(aws_findings) == 2
        assert len({f.fingerprint for f in aws_findings}) == 1
