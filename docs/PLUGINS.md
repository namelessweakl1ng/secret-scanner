# Plugin Guide

Secret Scanner supports a lightweight plugin system via Python entry points.
Plugins can add custom detectors, scanners, or reporters.

## Plugin Discovery

Plugins are discovered via the `secret_scanner.plugins` entry point group.
A plugin is any Python package that registers one or more entry points.

## Creating a Plugin

### 1. Create a Python package

```
my-secret-scanner-plugin/
├── pyproject.toml
└── my_plugin/
    └── __init__.py
```

### 2. Implement your plugin

```python
# my_plugin/__init__.py
from secret_scanner.detectors import Engine
from secret_scanner.models import Finding, ScanContext


class MyCustomDetector:
    """A custom detector that runs alongside the built-in engine."""

    def scan_line(self, line: str, ctx: ScanContext) -> list[Finding]:
        # Your custom detection logic here.
        # Return a list of Finding objects (empty if no match).
        if "MY_CUSTOM_PATTERN" in line:
            return [Finding(
                rule_id="custom:my_detector",
                rule_name="My Custom Detector",
                provider="custom",
                severity=Severity.HIGH,
                confidence=85,
                file_path=ctx.file_path,
                line_number=ctx.line_number,
                matched_value="MY_CUSTOM_PATTERN",
                detected_by="custom",
            )]
        return []


def register_engine_plugin(engine: Engine) -> None:
    """Hook called by secret-scanner to register your detector."""
    engine.add_custom_detector(MyCustomDetector())
```

### 3. Register the entry point

In your `pyproject.toml`:

```toml
[project.entry-points."secret_scanner.plugins"]
my_detector = "my_plugin:register_engine_plugin"
```

### 4. Install and use

```bash
pip install my-secret-scanner-plugin
secret-scanner scan .   # your plugin runs automatically
```

## Plugin API Reference

### Engine hooks

The `Engine` class exposes these methods for plugins:

- `add_custom_detector(detector)`: Add an object with a `scan_line(line, ctx) -> list[Finding]` method.
- `add_rule(rule: Rule)`: Add a single rule at runtime.
- `add_rules(rules: list[Rule])`: Add multiple rules at runtime.

### Reporter hooks

To add a custom output format:

```python
# my_plugin/__init__.py
from secret_scanner.reporters.base import Reporter


class MyXMLReporter(Reporter):
    def render(self, result) -> str:
        # ... build XML
        return xml


def register_reporter(format_map: dict) -> None:
    format_map["xml"] = MyXMLReporter
```

Register via entry point:

```toml
[project.entry-points."secret_scanner.reporters"]
xml = "my_plugin:register_reporter"
```

## Best Practices

1. **Plugins should be optional.** The scanner must work without any
   plugins installed.
2. **Plugins should not crash the scanner.** Wrap your detection logic in
   try/except and return an empty list on error.
3. **Plugins should respect the config.** Read `engine.config` for
   thresholds and feature flags.
4. **Plugins should not upload data.** Plugins run with the same
   privileges as the scanner; they should never send secrets or scan
   results over the network.

## Plugin Examples

See `examples/plugins/` in the repository for working examples.
