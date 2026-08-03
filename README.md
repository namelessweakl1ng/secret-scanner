# Secret Scanner

Production-grade secret scanner that detects accidentally leaked credentials, API keys, tokens, private keys, and other confidential information across:

- Local files and directories (recursive)
- Git repositories (working tree + full history + branches + stashes)
- GitHub / GitLab / Bitbucket repositories (public + private)
- GitHub Gists
- Archive files (ZIP, TAR, GZ, JAR, WAR, APK, ...)
- Raw URLs

Works completely offline for local scans. Cross-platform: Windows, Linux, macOS. Python 3.11+.

## Install

```bash
pip install secret-scanner
# or
uv tool install secret-scanner
# or
pipx install secret-scanner
```

## Quick Start

```bash
# Scan the current directory
secret-scanner scan .

# Scan a folder
secret-scanner scan ~/projects

# Scan a GitHub repo (public)
secret-scanner github owner/repo

# Scan a GitHub repo (private — set GITHUB_TOKEN)
GITHUB_TOKEN=ghp_xxx secret-scanner github owner/private-repo

# Scan a GitLab repo
secret-scanner gitlab https://gitlab.com/group/project

# Scan git history (commits, branches, stashes)
secret-scanner history .

# Audit a path: local scan + git history + HTML dashboard
secret-scanner audit .

# Scan an archive
secret-scanner archive project.zip

# Scan a GitHub gist
secret-scanner gist https://gist.github.com/user/abc123
```

## Detection Engine

The scanner layers four signals:

1. **Regex rules** — 60+ provider-specific patterns (AWS, Azure, GCP, GitHub, GitLab, OpenAI, Anthropic, Stripe, Discord, Slack, Telegram, JWT, private keys, database URLs, ...). See `secret-scanner rules` to list them all.
2. **Entropy** — Shannon entropy catches high-entropy random strings (base64, hex, JWT segments) that don't match any known pattern.
3. **Context** — variable names like `password`, `secret`, `token`, `api_key`, `bearer` near a match boost confidence.
4. **Path** — sensitive file names (`.env`, `id_rsa`, `credentials.json`, `.aws/credentials`, `.terraform.tfstate`, ...) are findings on their own.

A weighted scoring formula combines these into a 0-100 confidence score and a severity (Critical / High / Medium / Low / Info).

## Output Formats

```bash
secret-scanner scan . --format json   --output report.json
secret-scanner scan . --format csv    --output report.csv
secret-scanner scan . --format markdown --output report.md
secret-scanner scan . --format html   --output report.html
secret-scanner scan . --format sarif  --output report.sarif
secret-scanner scan . --format terminal   # default
```

The HTML report is a self-contained dashboard with severity charts, risk score gauge, top providers chart, and a sortable findings table.

## Severity and Exit Codes

| Severity | Description | Exit Code |
|----------|-------------|-----------|
| Critical | AWS keys, private keys, GitHub PATs, OpenAI keys, seed phrases | 4 |
| High     | JWT secrets, bearer tokens, webhook secrets, OAuth secrets | 3 |
| Medium   | Password-like strings, unknown tokens | 2 |
| Low      | Suspicious entropy | 1 |
| Info     | Potential sensitive config | 0 |

Use `--fail-on <severity>` to control when the scanner exits non-zero (useful for CI):

```bash
secret-scanner scan . --fail-on high   # exit non-zero if any HIGH or CRITICAL findings
```

## Configuration

Create `secret-scanner.yaml` in your project root:

```yaml
min_entropy: 4.5
min_length: 12
max_file_size_mb: 20
workers: 8

use_gitignore: true
ignore:
  - "tests/fixtures/**"
  - "*.sample"
ignore_regex:
  - "^vendor/.+$"

# Custom rule files (merged with built-ins)
rules:
  - ./my-rules.yaml

# Severity overrides
severity_overrides:
  discord_bot_token: medium

fail_on_severity: high
```

## Baseline Mode

Suppress known findings so only **new** leaks are reported:

```bash
# Save current findings as the baseline
secret-scanner baseline .

# Subsequent scans suppress baseline findings
secret-scanner scan . --baseline
```

## Ignore System

- `.gitignore` (respected by default, use `use_gitignore: false` to disable)
- `.secretignore` (gitignore-style syntax, always loaded if present)
- `--ignore` and `--ignore-regex` flags / config

## Git Hooks

Install a `pre-commit` hook that runs the scanner before each commit:

```bash
secret-scanner install-hooks .
secret-scanner install-hooks . --hook pre-push
```

## CI Integration

### GitHub Actions

```yaml
name: Secret Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install secret-scanner
      - run: secret-scanner scan . --fail-on high --format sarif --output scan.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: scan.sarif
```

### GitLab CI

```yaml
secret-scan:
  image: python:3.11
  script:
    - pip install secret-scanner
    - secret-scanner scan . --fail-on high --format json --output scan.json
  artifacts:
    paths:
      - scan.json
```

## Security

- **Never uploads files** unless explicitly requested (e.g., `github`, `gist`, `url` commands).
- **Offline mode** for `scan`, `history`, `audit`, `archive` — no network access.
- **Temporary files securely deleted** (overwrite + unlink) after archive scanning.
- **ZIP Slip protection** — refuses to extract archive entries that escape the dest directory.
- **ReDoS mitigation** — regex patterns are pre-compiled and bounded; long lines are skipped.
- **Secrets never printed in full** — every finding is masked (e.g., `sk-****...P9F`).
- **Fingerprinting** — secrets are SHA-256 hashed (with a domain separator) for deduplication and baselining, without ever persisting plaintext.

## Architecture

```
secret_scanner/
├── cli/          # Typer CLI + Rich output
├── scanners/     # local, git, github, gitlab, bitbucket, gist, archive, url
├── detectors/    # detection engine (regex + entropy + context + scoring)
├── rules/        # YAML rule loader + built-in rule data
├── reporters/    # terminal, json, csv, markdown, html, sarif
├── utils/        # file IO, ignore matcher, path safety
├── config/       # YAML config loader
├── git/          # git subprocess wrapper (history, blame, branches)
├── cache/        # SQLite scan history + baseline
└── models/       # Pydantic models: Finding, ScanResult, Severity
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
black .
```

## License

MIT
