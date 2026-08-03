# Architecture

This document describes the internal architecture of Secret Scanner for
contributors and integrators.

## High-Level Design

Secret Scanner is built as a **layered pipeline**:

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌────────────┐
│   Source    │ -> │   Scanner    │ -> │   Engine    │ -> │  Reporter  │
│ (file/git/  │    │ (walks and   │    │ (detection: │    │ (terminal/ │
│  URL/...)   │    │  yields text)│    │  regex+ent) │    │  json/html)│
└─────────────┘    └──────────────┘    └─────────────┘    └────────────┘
                         |                    |                  ^
                         v                    v                  |
                    ┌──────────┐         ┌─────────┐             |
                    │  Models  │ <-----  │  Rules  │ (YAML data)  │
                    │ (Finding,│         └─────────┘             │
                    │  ScanRes)│                                 │
                    └──────────┘ <-------------------------------┘
```

### Layers

1. **Models** (`secret_scanner/models/`): Pure data classes. `Finding`,
   `ScanResult`, `Severity`. No I/O. These are the contract between layers.

2. **Rules** (`secret_scanner/rules/`): YAML data files + a `RuleSet` loader.
   Rules are data-driven — adding a new provider means adding a YAML entry,
   not editing Python.

3. **Detectors** (`secret_scanner/detectors/`): The `Engine` class. Pure
   function: `(line, context) -> list[Finding]`. Combines regex, entropy,
   context, and path detection with a weighted scoring formula.

4. **Scanners** (`secret_scanner/scanners/`):
   - `LocalScanner`: walks directories, scans text files, recurses into
     archives.
   - `ArchiveScanner`: extracts ZIP/TAR safely, delegates to `LocalScanner`,
     securely deletes the temp dir.
   - `GitScanner`: walks git history (commits, branches, stashes, tags).
   - `GitHubScanner`, `GitLabScanner`, `BitbucketScanner`, `GistScanner`,
     `RawURLScanner`: clone or download to a temp dir, delegate to
     `GitScanner` or `LocalScanner`, securely delete.

5. **Reporters** (`secret_scanner/reporters/`): Convert `ScanResult` to
   terminal, JSON, CSV, Markdown, HTML, or SARIF. Each reporter is a
   subclass of `Reporter`.

6. **Config** (`secret_scanner/config/`): Loads `secret-scanner.yaml`,
   merges with defaults, applies severity overrides and custom rule files.

7. **Cache** (`secret_scanner/cache/`): SQLite database for scan history
   and baseline fingerprints. Lives at `~/.cache/secret-scanner/history.db`.

8. **CLI** (`secret_scanner/cli/`): Typer app with Rich output. Thin
   wrapper that wires config → scanner → reporter.

## Detection Pipeline

The `Engine.scan_line(line, ctx)` method is the hot path. It runs in three
phases:

### Phase 1: Regex rules
- Iterate all rules from the `RuleSet`.
- For each rule, `finditer` over the line.
- Collect all candidate matches as `(start, end, rule, match)` tuples.
- **Sort** by: exact_format rules first, then longer matches, then earlier
  position. This ensures the most specific rule wins on overlap.
- Walk the sorted candidates; skip any that overlap an already-accepted
  match (prevents duplicate findings for the same span).

### Phase 2: Entropy detection
- Extract candidate tokens: quoted strings, bare base64/hex runs, JWT-like
  patterns.
- For each, compute Shannon entropy.
- If entropy ≥ `min_entropy` (default 4.5 bits/symbol), emit an
  `entropy:high` finding.
- Skip tokens that overlap an already-accepted span.

### Phase 3: Path detection (called separately)
- For sensitive file paths (`.env`, `id_rsa`, `credentials.json`, ...),
  emit a finding purely based on the file name.

## Scoring Formula

Each signal contributes points:

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

- **Critical**: Known critical provider + exact format + confidence ≥ 70.
  (AWS keys, private keys, GitHub PATs, OpenAI keys, seed phrases, ...)
- **High**: Known critical provider with confidence ≥ 60, OR known
  high-severity provider with confidence ≥ 60, OR generic confidence ≥ 70.
  (JWT secrets, bearer tokens, webhook secrets, OAuth, Stripe, ...)
- **Medium**: Confidence ≥ 50. (Password-like strings, unknown tokens.)
- **Low**: Confidence ≥ 30. (Suspicious entropy.)
- **Info**: Below 30. (Potential sensitive config.)

## Threading Model

The `LocalScanner` uses `ThreadPoolExecutor` with a configurable number of
workers (default 4). Each worker scans one file independently. The
`Engine` is stateless and thread-safe.

The `GitScanner` is single-threaded for now (history scanning is
sequential per ref to keep memory bounded).

## Security Considerations

- **Secrets never printed in full.** Every `Finding` computes a
  `masked_value` that preserves only the first 4 and last 4 characters.
- **Fingerprinting without plaintext.** The `fingerprint` field is a
  SHA-256 hash of the secret salted with a domain-separation string. This
  allows deduplication and baselining without persisting plaintext.
- **ZIP Slip protection.** `safe_extract_zip` and `safe_extract_tar`
  reject absolute paths, `..` traversal, symlinks, and device files.
- **ReDoS mitigation.** All rule regexes are pre-compiled at startup.
  Lines longer than `max_line_length` (default 100,000 chars) are skipped.
- **Secure temp file deletion.** After archive scanning, the extracted
  temp directory is overwritten with zeros and unlinked.
- **No network in offline mode.** The `scan`, `history`, `audit`, and
  `archive` commands never touch the network. Only `github`, `gitlab`,
  `bitbucket`, `gist`, and `url` do, and they require explicit invocation.

## Adding a New Detector

1. Add a YAML entry under `secret_scanner/rules/data/<category>.yaml`:

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

2. If the provider needs a custom recommendation, add a branch to
   `default_recommendation` in `secret_scanner/models/__init__.py`.

3. Add a test fixture in `tests/samples.py` and a test in
   `tests/test_detectors.py`.

That's it — no Python code changes required for a new regex rule.

## Adding a New Reporter

1. Create `secret_scanner/reporters/<name>.py` with a class subclassing
   `Reporter`.
2. Implement `render(self, result: ScanResult) -> str`.
3. Register it in `secret_scanner/reporters/__init__.py` `FORMAT_MAP`.
4. Add tests in `tests/test_reporters.py`.

## Adding a New Scanner

1. Create `secret_scanner/scanners/<name>.py` with a class that returns a
   `ScanResult`.
2. The scanner should accept a `ScanConfig` and `Engine` in its
   constructor for dependency injection.
3. Register it in `secret_scanner/scanners/__init__.py`.
4. Add a Typer command in `secret_scanner/cli/main.py`.
5. Add tests.

## Performance Characteristics

- Scanning throughput: ~50-200 MB/s on a modern laptop, depending on rule
  count and file types.
- Memory: O(1) per file (lines are streamed, not buffered).
- Rule count: O(n) per line where n is the number of rules. With ~120
  rules, a 1000-line file takes ~50ms.
- Git history: O(commits × files). For a 1000-commit repo with 100 files
  per commit on average, expect ~30 seconds.

## Testing

Tests use `pytest` with `pytest-cov`. Integration tests that require git
are skipped if `git` is not installed.

```bash
pytest                    # all tests
pytest --no-cov           # skip coverage
pytest -m "not slow"      # skip slow tests
pytest tests/test_detectors.py  # one module
```
