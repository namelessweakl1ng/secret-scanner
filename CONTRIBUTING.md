# Contributing to Secret Scanner

Thanks for your interest in contributing! This document covers the basics.

## Development Setup

```bash
git clone https://github.com/secret-scanner/secret-scanner.git
cd secret-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Verify everything works:

```bash
pytest
ruff check .
black --check .
```

## Code Style

- Python 3.11+ (use modern syntax: `X | None`, `match` statements where appropriate).
- Fully type-hinted (run `mypy secret_scanner` to check).
- `black` for formatting (line length 100).
- `ruff` for linting.
- PEP 8 compliant (enforced by `ruff`).
- Docstrings on all public modules, classes, and functions.

## Adding a New Detection Rule

The easiest way to contribute. Add a YAML entry to
`secret_scanner/rules/data/<category>.yaml`:

```yaml
- id: myprovider_api_key
  name: MyProvider API Key
  provider: myprovider
  pattern: 'myprefix_[A-Za-z0-9]{32}'
  severity: high
  exact_format: true
  min_length: 32
  description: MyProvider API key
  tags: [myprovider, api_key]
```

Then add a test:

```python
# tests/test_detectors.py
def test_myprovider_key(self) -> None:
    eng = make_engine()
    line = 'KEY = "myprefix_abcdefghijklmnopqrstuvwxyz123456"'
    ctx = ScanContext(file_path="config.py", line_number=1, line_text=line)
    findings = eng.scan_line(line, ctx)
    assert any("myprovider" in f.rule_id for f in findings)
```

## Adding a New Reporter

1. Create `secret_scanner/reporters/<name>.py`:

```python
from .base import Reporter

class XMLReporter(Reporter):
    def render(self, result) -> str:
        # ... build XML string
        return xml_string
```

2. Register in `secret_scanner/reporters/__init__.py`:
```python
from .xml import XMLReporter
FORMAT_MAP["xml"] = XMLReporter
```

3. Add tests in `tests/test_reporters.py`.

## Adding a New Scanner

1. Create `secret_scanner/scanners/<name>.py`:

```python
class MyScanner:
    def __init__(self, config, engine, *, show_progress=True):
        self.config = config
        self.engine = engine

    def scan(self, target) -> ScanResult:
        result = ScanResult(target=str(target), scan_type="mytype")
        # ... do the scan
        return result
```

2. Add a CLI command in `secret_scanner/cli/main.py`.

3. Add tests.

## Testing Guidelines

- Aim for 90%+ coverage on new code.
- Use `pytest` fixtures for shared setup.
- Mock network calls — never hit real services in tests.
- Use `tmp_path` for filesystem tests.
- For git tests, create real temp git repos via subprocess (see
  `tests/test_git_scanner.py`).
- For archive tests, build archives in-memory (see
  `tests/test_archive_scanner.py`).

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Notion integration token detector
fix: prevent duplicate entropy findings on same span
docs: add CONTRIBUTING guide
test: add tests for archive scanner
refactor: extract URL parsing into helper
```

## Pull Request Process

1. Fork the repo and create a feature branch.
2. Write tests for your changes.
3. Ensure `pytest`, `ruff check .`, and `black --check .` all pass.
4. Update the README if you added a user-facing feature.
5. Open a PR with a clear description of what changed and why.

## Release Process

1. Bump version in `pyproject.toml` and `secret_scanner/__init__.py`.
2. Update `CHANGELOG.md`.
3. Tag with `v1.2.3`.
4. GitHub Actions builds and publishes to PyPI automatically.

## Security Vulnerability Reporting

**Do not open a public issue for security vulnerabilities.** Email
security@secret-scanner.example instead. See `SECURITY.md` for details.

## Code of Conduct

Be excellent to each other. Harassment of any kind will not be tolerated.
