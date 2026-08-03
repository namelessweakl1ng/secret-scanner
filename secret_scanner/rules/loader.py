"""Rule loader and rule set data structures.

Rules are stored as YAML files under ``secret_scanner/rules/data/*.yaml`` so
that users can inspect, override, and extend them without touching Python
code. Each rule has the schema::

    id: aws_access_key
    name: AWS Access Key
    provider: aws_access_key
    pattern: 'AKIA[0-9A-Z]{16}'
    severity: critical
    exact_format: true
    min_length: 16
    max_length: 256
    description: AWS access key ID

Multiple files are merged; user-supplied rules (via config) can override
built-ins by ``id``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..models import Severity

# Resolve the data directory relative to this file.
_DATA_DIR = Path(__file__).parent / "data"


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    id: str
    name: str
    provider: str
    pattern: str
    severity: Severity = Severity.MEDIUM
    exact_format: bool = False
    min_length: int = 8
    max_length: int = 4096
    description: str = ""
    tags: list[str] = field(default_factory=list)
    # Compiled lazily on first access via property.
    _compiled: re.Pattern[str] | None = None

    @property
    def compiled(self) -> re.Pattern[str]:
        """Return the compiled regex (cached)."""
        if self._compiled is None:
            # Wrap in a group to ensure finditer returns the whole match.
            try:
                pattern = self.pattern
                object.__setattr__(self, "_compiled", re.compile(pattern))
            except re.error as exc:
                # A malformed rule should not crash the whole scan.
                # Replace with a never-matching pattern and store the error.
                object.__setattr__(self, "_compiled", re.compile(r"(?!x)x"))
                object.__setattr__(
                    self, "description", f"[INVALID REGEX: {exc}] {self.description}"
                )
        return self._compiled  # type: ignore[return-value]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        """Build a Rule from a YAML dict."""
        sev_raw = data.get("severity", "medium")
        sev = Severity.parse(sev_raw) if isinstance(sev_raw, str) else Severity(sev_raw)
        return cls(
            id=str(data["id"]),
            name=str(data.get("name", data["id"])),
            provider=str(data.get("provider", "generic")),
            pattern=str(data["pattern"]),
            severity=sev,
            exact_format=bool(data.get("exact_format", False)),
            min_length=int(data.get("min_length", 8)),
            max_length=int(data.get("max_length", 4096)),
            description=str(data.get("description", "")),
            tags=list(data.get("tags", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize back to a dict (for user inspection / custom rules)."""
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider,
            "pattern": self.pattern,
            "severity": self.severity.name.lower(),
            "exact_format": self.exact_format,
            "min_length": self.min_length,
            "max_length": self.max_length,
            "description": self.description,
            "tags": self.tags,
        }


class RuleSet:
    """An ordered collection of rules with O(1) lookup by id."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules: list[Rule] = list(rules or [])
        self._by_id: dict[str, Rule] = {r.id: r for r in self._rules}

    def __iter__(self):
        return iter(self._rules)

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._by_id

    def get(self, rule_id: str) -> Rule | None:
        """Return a rule by id, or None."""
        return self._by_id.get(rule_id)

    def add(self, rule: Rule) -> None:
        """Add or replace a rule by id."""
        if rule.id in self._by_id:
            # Replace in-place to preserve order.
            for i, existing in enumerate(self._rules):
                if existing.id == rule.id:
                    self._rules[i] = rule
                    break
        else:
            self._rules.append(rule)
        self._by_id[rule.id] = rule

    def merge(self, other: RuleSet) -> RuleSet:
        """Return a new RuleSet with rules from both, ``other`` taking precedence."""
        merged = RuleSet(list(self._rules))
        for rule in other:
            merged.add(rule)
        return merged

    def filter_by_tag(self, tag: str) -> RuleSet:
        """Return a new RuleSet containing only rules with the given tag."""
        return RuleSet([r for r in self._rules if tag in r.tags])

    def filter_by_provider(self, provider: str) -> RuleSet:
        """Return a new RuleSet containing only rules for the given provider."""
        return RuleSet([r for r in self._rules if r.provider == provider])


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def _load_yaml_file(path: Path) -> list[Rule]:
    """Load rules from a single YAML file."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuntimeError(f"Failed to load rules from {path}: {exc}") from exc

    if data is None:
        return []
    if isinstance(data, dict) and "rules" in data:
        items = data["rules"]
    elif isinstance(data, list):
        items = data
    else:
        raise RuntimeError(f"Unexpected YAML structure in {path}")
    return [Rule.from_dict(item) for item in items]


def load_default_ruleset() -> RuleSet:
    """Load the built-in rule set from the packaged data directory."""
    rules: list[Rule] = []
    if not _DATA_DIR.exists():
        return RuleSet(rules)
    for yaml_file in sorted(_DATA_DIR.glob("*.yaml")):
        rules.extend(_load_yaml_file(yaml_file))
    return RuleSet(rules)


def load_ruleset_from_file(path: str | Path) -> RuleSet:
    """Load a custom rule set from a single YAML file."""
    return RuleSet(_load_yaml_file(Path(path)))


def load_ruleset_from_dir(path: str | Path) -> RuleSet:
    """Load a rule set by merging all ``*.yaml`` files in a directory."""
    p = Path(path)
    rules: list[Rule] = []
    for yaml_file in sorted(p.glob("*.yaml")):
        rules.extend(_load_yaml_file(yaml_file))
    return RuleSet(rules)


__all__ = [
    "Rule",
    "RuleSet",
    "load_default_ruleset",
    "load_ruleset_from_file",
    "load_ruleset_from_dir",
]
