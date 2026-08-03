"""Tests for the cache module (SQLite history + baseline)."""

from __future__ import annotations

from pathlib import Path

from secret_scanner.cache import Cache
from secret_scanner.models import Finding, ScanResult, Severity


def make_result(*, findings_count: int = 3) -> ScanResult:
    r = ScanResult(target="test", scan_type="local")
    r.findings = [
        Finding(
            rule_id=f"r{i}",
            rule_name=f"R{i}",
            provider="generic",
            severity=Severity.HIGH,
            confidence=70 + i,
            file_path=f"f{i}.py",
            line_number=i + 1,
            matched_value=f"secret-{i}-0123456789",
        )
        for i in range(findings_count)
    ]
    return r


class TestCache:
    def test_record_scan(self, tmp_path: Path) -> None:
        cache = Cache(db_path=tmp_path / "test.db")
        r = make_result(findings_count=3)
        scan_id = cache.record_scan(r)
        assert scan_id > 0
        scans = cache.list_scans()
        assert len(scans) == 1
        assert scans[0]["findings_count"] == 3

    def test_baseline_save_and_load(self, tmp_path: Path) -> None:
        cache = Cache(db_path=tmp_path / "test.db")
        r = make_result(findings_count=3)
        count = cache.save_baseline(r)
        assert count == 3
        loaded = cache.load_baseline_fingerprints()
        assert len(loaded) == 3
        # Compare against the original fingerprints.
        for f in r.findings:
            assert f.fingerprint in loaded

    def test_baseline_replacement(self, tmp_path: Path) -> None:
        cache = Cache(db_path=tmp_path / "test.db")
        # First baseline.
        r1 = make_result(findings_count=3)
        cache.save_baseline(r1)
        assert cache.baseline_count() == 3
        # Replace with smaller baseline.
        r2 = make_result(findings_count=2)
        cache.save_baseline(r2)
        assert cache.baseline_count() == 2

    def test_baseline_empty(self, tmp_path: Path) -> None:
        cache = Cache(db_path=tmp_path / "test.db")
        assert cache.load_baseline_fingerprints() == set()
        assert cache.baseline_count() == 0

    def test_multiple_scans_history(self, tmp_path: Path) -> None:
        cache = Cache(db_path=tmp_path / "test.db")
        for i in range(5):
            cache.record_scan(make_result(findings_count=i + 1))
        scans = cache.list_scans(limit=10)
        assert len(scans) == 5
