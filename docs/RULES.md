# Rule Authoring Guide

This guide explains how to write, test, and contribute new detection rules.

## Rule Schema

Each rule is a YAML object with these fields:

| Field           | Type     | Required | Default     | Description                                             |
|-----------------|----------|----------|-------------|---------------------------------------------------------|
| `id`            | string   | yes      |             | Unique identifier (e.g., `aws_access_key_id`).          |
| `name`          | string   | no       | = `id`      | Human-readable name.                                    |
| `provider`      | string   | no       | `generic`   | Provider/category (used for recommendations and stats). |
| `pattern`       | string   | yes      |             | Python regex (no delimiters).                           |
| `severity`      | string   | no       | `medium`    | One of `critical`, `high`, `medium`, `low`, `info`.    |
| `exact_format`  | bool     | no       | `false`     | True if the pattern exactly matches the provider format.|
| `min_length`    | int      | no       | `8`         | Minimum match length to accept.                         |
| `max_length`    | int      | no       | `4096`      | Maximum match length to accept.                         |
| `description`   | string   | no       | `""`        | Human-readable description.                             |
| `tags`          | string[] | no       | `[]`        | Tags for filtering (e.g., `aws`, `cloud`, `api_key`).   |

## Authoring Patterns

### Provider-specific patterns

Always include the provider's prefix or format signature:

```yaml
- id: stripe_secret_key
  pattern: 'sk_live_[0-9a-zA-Z]{24,}'
  exact_format: true
```

Use `exact_format: true` when the pattern uniquely identifies the provider.
This boosts the confidence score and can promote to Critical severity.

### Context-required patterns

For patterns that could be false positives on their own, require a
sensitive variable name nearby:

```yaml
- id: aws_secret_access_key
  pattern: '(?i)aws(.{0,20})?(secret|sk|secret_access_key)[\s:=]+["'']?([A-Za-z0-9/+=]{40})["'']?'
```

The `(?i)` flag makes the regex case-insensitive. The `[\s:=]+` matches
whitespace, `=`, or `:` between key and value.

### Anchoring

Avoid `^` and `$` anchors — they prevent matching secrets embedded in
longer lines. Use word boundaries `\b` instead:

```yaml
pattern: '\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}\b'  # Discord bot token
```

### Avoid ReDoS

Avoid nested quantifiers like `(a+)+` which can cause catastrophic
backtracking. If a pattern is complex, test it against adversarial input.

## Confidence Scoring

The engine combines these signals:

| Signal                    | Points |
|---------------------------|--------|
| Regex match               | 40     |
| Exact provider format     | 15     |
| Known provider            | 10     |
| High entropy (≥4.5)       | 15     |
| Moderate entropy (>3.5)   | 5      |
| Sensitive variable name   | 15     |
| Sensitive file path       | 10     |
| Min length satisfied      | 5      |

Total is capped at 100.

## Severity Mapping

- **Critical**: critical provider + exact format + confidence ≥ 70.
- **High**: high provider + confidence ≥ 60, OR generic confidence ≥ 70.
- **Medium**: confidence ≥ 50.
- **Low**: confidence ≥ 30.
- **Info**: confidence < 30.

The `critical_providers` and `high_providers` sets are defined in
`secret_scanner/detectors/__init__.py`.

## Overlap Resolution

When multiple rules match the same span, the engine picks the winner:

1. `exact_format` rules beat non-exact rules.
2. Longer matches beat shorter matches.
3. Earlier positions beat later positions.

This ensures `ghp_[A-Za-z0-9]{36}` (specific GitHub PAT) wins over a
generic `token_assignment` rule on the same span.

## Testing Rules

Add a test that exercises your new rule:

```python
# tests/test_detectors.py
def test_myprovider_key(self) -> None:
    eng = make_engine()
    line = 'KEY = "myprefix_abcdefghijklmnopqrstuvwxyz123456"'
    ctx = ScanContext(file_path="config.py", line_number=1, line_text=line)
    findings = eng.scan_line(line, ctx)
    assert any(f.rule_id == "myprovider_api_key" for f in findings)
    assert findings[0].severity == Severity.HIGH
```

## Listing and Filtering Rules

```bash
# List all rules
secret-scanner rules

# Filter by provider
secret-scanner rules --provider aws_access_key

# Filter by tag
secret-scanner rules --tag cloud

# JSON output for piping
secret-scanner rules --format json
```

## Custom Rules via Config

Users can add custom rules without modifying the package:

```yaml
# secret-scanner.yaml
rules:
  - ./my-custom-rules.yaml
```

Custom rules are merged with built-ins. Rules with the same `id` override
built-ins.

## Severity Overrides

Users can downgrade or upgrade built-in rules:

```yaml
# secret-scanner.yaml
severity_overrides:
  discord_bot_token: medium   # downgrade from high
  slack_token: critical       # upgrade from high
```
