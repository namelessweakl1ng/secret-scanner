"""Configuration system: load and validate secret-scanner.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..rules import RuleSet, load_default_ruleset, load_ruleset_from_file


@dataclass
class ScanConfig:
    """Runtime scan configuration.

    Built from defaults + ``secret-scanner.yaml`` (if present) + CLI flags.
    """

    # Detection tuning.
    min_entropy: float = 4.5
    min_length: int = 12
    max_length: int = 4096
    max_line_length: int = 100_000
    enable_entropy: bool = True
    enable_context: bool = True
    enable_path_rules: bool = True

    # File scanning.
    max_file_size_mb: int = 20
    follow_symlinks: bool = False

    # Ignore system.
    use_gitignore: bool = True
    ignore_globs: list[str] = field(default_factory=list)
    ignore_regexes: list[str] = field(default_factory=list)

    # Performance.
    workers: int = 4

    # Rules.
    ruleset: RuleSet = field(default_factory=load_default_ruleset)
    custom_rule_files: list[Path] = field(default_factory=list)

    # Severity overrides (rule_id -> severity).
    severity_overrides: dict[str, str] = field(default_factory=dict)

    # Allowlist of fingerprints to suppress (baseline mode).
    baseline_fingerprints: set[str] = field(default_factory=set)

    # Exit-code threshold: exit non-zero only if a finding of this severity
    # or higher is found. ``None`` means "always exit 0 unless findings".
    fail_on_severity: str | None = "low"

    @classmethod
    def from_file(cls, path: str | Path) -> ScanConfig:
        """Load config from a YAML file."""
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Config file not found: {p}")
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanConfig:
        """Build a ScanConfig from a dict (parsed YAML)."""
        cfg = cls()
        if "min_entropy" in data:
            cfg.min_entropy = float(data["min_entropy"])
        if "min_length" in data:
            cfg.min_length = int(data["min_length"])
        if "max_length" in data:
            cfg.max_length = int(data["max_length"])
        if "max_line_length" in data:
            cfg.max_line_length = int(data["max_line_length"])
        if "enable_entropy" in data:
            cfg.enable_entropy = bool(data["enable_entropy"])
        if "enable_context" in data:
            cfg.enable_context = bool(data["enable_context"])
        if "enable_path_rules" in data:
            cfg.enable_path_rules = bool(data["enable_path_rules"])
        if "max_file_size_mb" in data:
            cfg.max_file_size_mb = int(data["max_file_size_mb"])
        if "follow_symlinks" in data:
            cfg.follow_symlinks = bool(data["follow_symlinks"])
        if "use_gitignore" in data:
            cfg.use_gitignore = bool(data["use_gitignore"])
        if "ignore" in data and isinstance(data["ignore"], list):
            cfg.ignore_globs = list(data["ignore"])
        if "ignore_regex" in data and isinstance(data["ignore_regex"], list):
            cfg.ignore_regexes = list(data["ignore_regex"])
        if "workers" in data:
            cfg.workers = max(1, int(data["workers"]))
        if "fail_on_severity" in data:
            cfg.fail_on_severity = data["fail_on_severity"]
        if "severity_overrides" in data and isinstance(data["severity_overrides"], dict):
            cfg.severity_overrides = dict(data["severity_overrides"])
        # Custom rules.
        if "rules" in data and isinstance(data["rules"], list):
            for entry in data["rules"]:
                if isinstance(entry, str):
                    cfg.custom_rule_files.append(Path(entry))
        return cfg

    def apply_overrides(self) -> None:
        """Apply severity overrides and load custom rule files into the ruleset."""
        # Custom rule files.
        for path in self.custom_rule_files:
            if path.is_file():
                custom = load_ruleset_from_file(path)
                self.ruleset = self.ruleset.merge(custom)
        # Severity overrides.
        from ..models import Severity
        from ..rules.loader import Rule

        for rule_id, sev_str in self.severity_overrides.items():
            existing = self.ruleset.get(rule_id)
            if existing is None:
                continue
            try:
                new_sev = Severity.parse(sev_str)
            except ValueError:
                continue
            # Rules are frozen dataclasses; replace.
            new_rule = Rule(
                id=existing.id,
                name=existing.name,
                provider=existing.provider,
                pattern=existing.pattern,
                severity=new_sev,
                exact_format=existing.exact_format,
                min_length=existing.min_length,
                max_length=existing.max_length,
                description=existing.description,
                tags=existing.tags,
            )
            self.ruleset.add(new_rule)


def find_config(start: Path) -> Path | None:
    """Find a secret-scanner.yaml by walking up from ``start``."""
    current = start.resolve()
    while True:
        candidate = current / "secret-scanner.yaml"
        if candidate.is_file():
            return candidate
        # Also accept .secret-scanner.yaml
        candidate = current / ".secret-scanner.yaml"
        if candidate.is_file():
            return candidate
        if current.parent == current:
            return None
        current = current.parent


__all__ = ["ScanConfig", "find_config"]
