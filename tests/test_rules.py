"""Tests for the rule loader."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from secret_scanner.rules import (
    Rule,
    RuleSet,
    load_default_ruleset,
    load_ruleset_from_file,
)


class TestRuleSet:
    def test_load_default_has_rules(self) -> None:
        rs = load_default_ruleset()
        assert len(rs) >= 50  # we ship 100+ rules

    def test_get_by_id(self) -> None:
        rs = load_default_ruleset()
        rule = rs.get("aws_access_key_id")
        assert rule is not None
        assert rule.provider == "aws_access_key"
        assert rule.exact_format is True

    def test_filter_by_provider(self) -> None:
        rs = load_default_ruleset()
        aws_rules = rs.filter_by_provider("aws_access_key")
        assert len(aws_rules) >= 1
        for r in aws_rules:
            assert r.provider == "aws_access_key"

    def test_filter_by_tag(self) -> None:
        rs = load_default_ruleset()
        aws_tagged = rs.filter_by_tag("aws")
        assert len(aws_tagged) >= 2

    def test_merge_overrides_by_id(self) -> None:
        rs = load_default_ruleset()
        original = rs.get("aws_access_key_id")
        assert original is not None
        overridden = Rule(
            id="aws_access_key_id",
            name="Custom AWS Key",
            provider="aws_access_key",
            pattern="AKIA[0-9A-Z]{16}",
            severity=original.severity,
            exact_format=True,
        )
        merged = rs.merge(RuleSet([overridden]))
        assert merged.get("aws_access_key_id").name == "Custom AWS Key"
        # Original unchanged.
        assert rs.get("aws_access_key_id").name == "AWS Access Key ID"

    def test_add_replaces_in_place(self) -> None:
        rs = load_default_ruleset()
        original_len = len(rs)
        new_rule = Rule(
            id="custom:rule",
            name="Custom",
            provider="custom",
            pattern="custom[A-Z]{10}",
        )
        rs.add(new_rule)
        assert len(rs) == original_len + 1
        # Adding again should not duplicate.
        rs.add(new_rule)
        assert len(rs) == original_len + 1


class TestRule:
    def test_from_dict(self) -> None:
        data = {
            "id": "test",
            "name": "Test Rule",
            "provider": "test",
            "pattern": "test[A-Z]+",
            "severity": "high",
            "exact_format": True,
            "min_length": 5,
        }
        r = Rule.from_dict(data)
        assert r.id == "test"
        assert r.severity.name == "HIGH"
        assert r.exact_format is True

    def test_compiled_returns_pattern(self) -> None:
        r = Rule(id="t", name="t", provider="p", pattern="abc")
        assert r.compiled.search("abc") is not None

    def test_invalid_regex_does_not_crash(self) -> None:
        r = Rule(id="t", name="t", provider="p", pattern="[")  # invalid
        # Should compile to a never-matching pattern, not raise.
        assert r.compiled.search("anything") is None

    def test_to_dict_roundtrip(self) -> None:
        data = {
            "id": "test",
            "name": "Test",
            "provider": "p",
            "pattern": "test",
            "severity": "low",
        }
        r = Rule.from_dict(data)
        d = r.to_dict()
        assert d["id"] == "test"
        assert d["severity"] == "low"


class TestLoadFromFile:
    def test_load_yaml(self, tmp_path: Path) -> None:
        yaml_content = dedent("""
        rules:
          - id: custom:test
            name: Custom Test
            provider: custom
            pattern: 'CUSTOM[A-Z]{8}'
            severity: medium
        """)
        p = tmp_path / "rules.yaml"
        p.write_text(yaml_content)
        rs = load_ruleset_from_file(p)
        assert len(rs) == 1
        assert rs.get("custom:test") is not None

    def test_load_top_level_list(self, tmp_path: Path) -> None:
        yaml_content = dedent("""
        - id: a:b
          name: AB
          provider: p
          pattern: 'abc'
        - id: c:d
          name: CD
          provider: p
          pattern: 'def'
        """)
        p = tmp_path / "rules.yaml"
        p.write_text(yaml_content)
        rs = load_ruleset_from_file(p)
        assert len(rs) == 2
