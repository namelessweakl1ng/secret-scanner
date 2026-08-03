"""Tests for the reporters."""

from __future__ import annotations

import json
from pathlib import Path

from secret_scanner.models import Finding, ScanResult, Severity
from secret_scanner.reporters import (
    CSVReporter,
    HTMLReporter,
    JSONReporter,
    MarkdownReporter,
    SARIFReporter,
    TerminalReporter,
    get_reporter,
)


def make_result(*, findings: int = 3) -> ScanResult:
    r = ScanResult(target="test", scan_type="local")
    r.files_scanned = 10
    r.findings = [
        Finding(
            rule_id=f"rule:{i}",
            rule_name=f"Rule {i}",
            provider="generic" if i % 2 else "aws_access_key",
            severity=[Severity.CRITICAL, Severity.HIGH, Severity.LOW][i % 3],
            confidence=70 + i,
            file_path=f"file_{i}.py",
            line_number=i + 1,
            matched_value=f"secret-value-{i}-1234567890",
        )
        for i in range(findings)
    ]
    return r


class TestReporterFactory:
    def test_get_terminal(self) -> None:
        assert isinstance(get_reporter("terminal"), TerminalReporter)

    def test_get_json(self) -> None:
        assert isinstance(get_reporter("json"), JSONReporter)

    def test_get_markdown_alias(self) -> None:
        assert isinstance(get_reporter("md"), MarkdownReporter)

    def test_unknown_raises(self) -> None:
        try:
            get_reporter("bogus")
            raise AssertionError()
        except ValueError:
            pass


class TestJSONReporter:
    def test_renders_valid_json(self) -> None:
        r = make_result()
        out = JSONReporter().render(r)
        data = json.loads(out)
        assert data["target"] == "test"
        assert len(data["findings"]) == 3
        assert "stats" in data
        assert data["stats"]["findings"] == 3

    def test_includes_fingerprint(self) -> None:
        r = make_result()
        out = JSONReporter().render(r)
        data = json.loads(out)
        for f in data["findings"]:
            assert "fingerprint" in f
            assert len(f["fingerprint"]) == 64

    def test_no_plaintext_secret(self) -> None:
        r = make_result()
        out = JSONReporter().render(r)
        # The full secret value must never appear in the report.
        for f in r.findings:
            assert f.matched_value not in out

    def test_writes_to_file(self, tmp_path: Path) -> None:
        r = make_result()
        out_file = tmp_path / "report.json"
        JSONReporter().render_to_file(r, out_file)
        assert out_file.is_file()
        data = json.loads(out_file.read_text())
        assert len(data["findings"]) == 3


class TestCSVReporter:
    def test_renders_csv(self) -> None:
        r = make_result()
        out = CSVReporter().render(r)
        lines = out.strip().splitlines()
        # 1 header + N findings.
        assert len(lines) == 1 + 3
        assert "rule_id" in lines[0]

    def test_no_plaintext_secret(self) -> None:
        r = make_result()
        out = CSVReporter().render(r)
        for f in r.findings:
            assert f.matched_value not in out


class TestMarkdownReporter:
    def test_renders_markdown(self) -> None:
        r = make_result()
        out = MarkdownReporter().render(r)
        assert "# Secret Scanner Report" in out
        assert "Severity Breakdown" in out
        assert "Findings" in out

    def test_no_findings(self) -> None:
        r = ScanResult(target="x", scan_type="local")
        out = MarkdownReporter().render(r)
        assert "No secrets found" in out


class TestHTMLReporter:
    def test_renders_html(self) -> None:
        r = make_result()
        out = HTMLReporter().render(r)
        assert "<!DOCTYPE html>" in out
        assert "Secret Scanner Report" in out
        assert "<canvas" in out  # has charts

    def test_no_plaintext_secret(self) -> None:
        r = make_result()
        out = HTMLReporter().render(r)
        for f in r.findings:
            assert f.matched_value not in out

    def test_escapes_html(self) -> None:
        r = ScanResult(target="x", scan_type="local")
        r.findings = [
            Finding(
                rule_id="x",
                rule_name="<script>alert(1)</script>",
                provider="p",
                severity=Severity.HIGH,
                confidence=80,
                file_path="x",
                line_number=1,
                matched_value="secret-1234567890",
            )
        ]
        out = HTMLReporter().render(r)
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out


class TestSARIFReporter:
    def test_renders_sarif(self) -> None:
        r = make_result()
        out = SARIFReporter().render(r)
        data = json.loads(out)
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) == 3
        # Each result must have ruleId and level.
        for res in data["runs"][0]["results"]:
            assert "ruleId" in res
            assert "level" in res

    def test_rules_section_includes_all_unique_rules(self) -> None:
        r = make_result(findings=5)
        out = SARIFReporter().render(r)
        data = json.loads(out)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        # Should be 5 unique rule_ids.
        assert len(rules) == 5


class TestTerminalReporter:
    def test_renders_string(self) -> None:
        r = make_result()
        out = TerminalReporter().render(r)
        assert "Secret Scanner" in out
        assert "Scan Summary" in out

    def test_renders_no_findings(self) -> None:
        r = ScanResult(target="x", scan_type="local")
        out = TerminalReporter().render(r)
        assert "No secrets found" in out
