"""Tests for the models module.

All test secrets use ``SAMPLES`` (runtime-constructed) so that no literal
real-format secret pattern appears in the source file.
"""

from __future__ import annotations

import pytest

from secret_scanner.models import (
    Finding,
    ScanResult,
    Severity,
    fingerprint_secret,
    is_sensitive_variable_name,
    mask_secret,
)

from .samples import SAMPLES


class TestSeverity:
    def test_parse_string(self) -> None:
        assert Severity.parse("critical") is Severity.CRITICAL
        assert Severity.parse("HIGH") is Severity.HIGH
        assert Severity.parse("Medium") is Severity.MEDIUM

    def test_parse_invalid(self) -> None:
        with pytest.raises(ValueError):
            Severity.parse("bogus")

    def test_ordering(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO
        assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL

    def test_label(self) -> None:
        assert Severity.CRITICAL.label == "Critical"
        assert Severity.INFO.label == "Info"

    def test_rich_style(self) -> None:
        assert Severity.CRITICAL.rich_style == "bold red"
        assert Severity.INFO.rich_style == "dim"


class TestMaskSecret:
    def test_long_secret(self) -> None:
        # Use a runtime-constructed secret so no literal pattern appears.
        secret = SAMPLES["aws_access_key_id"]
        result = mask_secret(secret)
        assert result.startswith("AKIA")
        assert result.endswith("MPLE")
        assert "*" in result

    def test_short_secret(self) -> None:
        # Length <= visible_prefix + visible_suffix -> all stars
        assert mask_secret("abc") == "***"

    def test_boundary(self) -> None:
        # 8 chars = 4+4 -> all stars
        assert mask_secret("abcdefgh") == "********"

    def test_just_above_boundary_correct(self) -> None:
        # 9 chars: first 4 + stars + last 4
        result = mask_secret("abcdefghi")
        assert result.startswith("abcd")
        assert result.endswith("ghi")
        assert "*" in result

    def test_empty(self) -> None:
        assert mask_secret("") == ""


class TestFingerprint:
    def test_deterministic(self) -> None:
        assert fingerprint_secret("hello") == fingerprint_secret("hello")

    def test_different_inputs(self) -> None:
        assert fingerprint_secret("hello") != fingerprint_secret("world")

    def test_hex_string(self) -> None:
        fp = fingerprint_secret("test")
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)


class TestFinding:
    def _make_finding(self, **overrides) -> Finding:  # noqa: ANN001
        defaults = {
            "rule_id": "test:rule",
            "rule_name": "Test Rule",
            "provider": "generic",
            "severity": Severity.HIGH,
            "confidence": 80,
            "file_path": "config.py",
            "line_number": 10,
            "matched_value": "sk-test1234567890",
        }
        defaults.update(overrides)
        return Finding(**defaults)

    def test_finding_computes_fingerprint(self) -> None:
        f = self._make_finding()
        assert f.fingerprint
        assert len(f.fingerprint) == 64

    def test_finding_computes_mask(self) -> None:
        f = self._make_finding(matched_value=SAMPLES["aws_access_key_id"])
        assert f.masked_value.startswith("AKIA")
        assert f.masked_value.endswith("MPLE")

    def test_finding_has_recommendation(self) -> None:
        f = self._make_finding(provider="aws_secret_key")
        assert "rotate" in f.recommendation.lower()

    def test_severity_from_string(self) -> None:
        f = self._make_finding(severity="critical")
        assert f.severity is Severity.CRITICAL

    def test_to_sarif(self) -> None:
        f = self._make_finding()
        sarif = f.to_sarif()
        assert sarif["ruleId"] == "test:rule"
        assert sarif["level"] == "error"  # HIGH -> error
        assert sarif["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "config.py"


class TestScanResult:
    def test_empty_result(self) -> None:
        r = ScanResult(target=".", scan_type="local")
        assert r.finding_count == 0
        assert r.dominant_severity is Severity.INFO
        assert r.risk_score() == 0

    def test_severity_counts(self) -> None:
        r = ScanResult(target=".", scan_type="local")
        r.findings = [
            Finding(
                rule_id="a",
                rule_name="A",
                provider="p",
                severity=Severity.HIGH,
                confidence=80,
                file_path="a",
                line_number=1,
                matched_value="x",
            ),
            Finding(
                rule_id="b",
                rule_name="B",
                provider="p",
                severity=Severity.HIGH,
                confidence=80,
                file_path="b",
                line_number=1,
                matched_value="y",
            ),
            Finding(
                rule_id="c",
                rule_name="C",
                provider="p",
                severity=Severity.LOW,
                confidence=40,
                file_path="c",
                line_number=1,
                matched_value="z",
            ),
        ]
        counts = r.severity_counts()
        assert counts["High"] == 2
        assert counts["Low"] == 1
        assert counts["Critical"] == 0
        assert r.dominant_severity is Severity.HIGH
        assert r.unique_secrets == 3

    def test_risk_score_nonzero(self) -> None:
        r = ScanResult(target=".", scan_type="local")
        r.findings = [
            Finding(
                rule_id="a",
                rule_name="A",
                provider="aws",
                severity=Severity.CRITICAL,
                confidence=90,
                file_path="a",
                line_number=1,
                matched_value="aaaa",
            ),
        ]
        assert r.risk_score() > 0
        assert r.risk_score() <= 100


class TestSensitiveVariable:
    def test_password(self) -> None:
        assert is_sensitive_variable_name("password")

    def test_api_key(self) -> None:
        assert is_sensitive_variable_name("api_key")
        assert is_sensitive_variable_name("API_KEY")
        assert is_sensitive_variable_name("apiKey")

    def test_benign(self) -> None:
        assert not is_sensitive_variable_name("username")
        assert not is_sensitive_variable_name("color")
        assert not is_sensitive_variable_name("count")
