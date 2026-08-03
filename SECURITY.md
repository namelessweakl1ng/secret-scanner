# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Secret Scanner, please report
it responsibly:

1. **Do not open a public GitHub issue.**
2. Email security@secret-scanner.example with a description of the issue.
3. Include steps to reproduce if possible.
4. We will acknowledge within 48 hours and work with you on a fix.

## Security Guarantees

Secret Scanner is designed with these security properties:

### Secrets are never printed in full

Every detected secret is masked before display. Only the first 4 and last
4 characters are visible (e.g., `AKIA****************MPLE`). The full
plaintext secret never appears in:

- Terminal output
- JSON, CSV, Markdown, HTML, or SARIF reports
- SQLite cache
- Log messages

### Secrets are never persisted in plaintext

The SQLite cache stores SHA-256 fingerprints (with a domain-separation
salt), not plaintext secrets. This allows deduplication and baselining
without leaking secrets to disk.

### Offline mode is truly offline

The `scan`, `history`, `audit`, and `archive` commands never make network
requests. Only the explicitly network commands (`github`, `gitlab`,
`bitbucket`, `gist`, `url`) access the network, and they require an
explicit URL argument.

### Temporary files are securely deleted

When scanning archives or cloning remote repos, the scanner:

1. Creates a temp directory under the system temp location.
2. Extracts / clones into it.
3. Scans the contents.
4. Overwrites files with zeros and unlinks them.
5. Removes the temp directory.

This prevents secrets from lingering on disk after the scan completes.

### ZIP Slip protection

The archive extractors refuse to extract:

- Entries with absolute paths (e.g., `/etc/passwd`)
- Entries with `..` traversal components (e.g., `../../etc/evil`)
- Symlinks pointing outside the destination
- Special device files

### ReDoS mitigation

All regex patterns are pre-compiled at startup. Patterns that fail to
compile are replaced with a never-matching pattern (and flagged in the
rule description). Lines longer than `max_line_length` (default 100,000
characters) are skipped to prevent pathological regex backtracking.

### Path sanitization

All file paths are resolved relative to the scan root. Paths that escape
the root (via `..` or symlinks) are rejected.

### No command injection

The scanner does not invoke any shell commands with user-supplied input.
The only subprocess calls are to `git` with structured argument lists
(not shell strings).

## Threat Model

### What Secret Scanner protects against

- Accidental secret leaks in source code committed to version control.
- Secrets in configuration files that get bundled into containers or
  archives.
- Secrets in git history that were deleted but never rotated.

### What Secret Scanner does NOT protect against

- Secrets in encrypted files (it scans plaintext only).
- Secrets in binary files (it skips them, except archives).
- Secrets that have been deliberately obfuscated (e.g., base64-encoded
  and split across files — though entropy detection may catch some cases).
- Zero-day or unknown provider formats (the rule set is updated as new
  providers are added).
- Active exfiltration by a malicious insider with commit access.

### False positives

Secret Scanner may produce false positives on:

- Test fixtures that contain realistic-looking but fake secrets.
- Documentation that describes secret formats with examples.
- Code that handles secrets abstractly (e.g., a function parameter named
  `api_key`).

Use `.secretignore`, the `--baseline` flag, or severity overrides in
`secret-scanner.yaml` to suppress known false positives.

## Disclosure Timeline

- **Day 0**: Vulnerability reported.
- **Day 1**: Acknowledgement sent.
- **Day 7**: Initial assessment and triage.
- **Day 30**: Fix developed and tested.
- **Day 45**: Coordinated public disclosure with CVE if applicable.

## Contact

- Security reports: security@secret-scanner.example
- General questions: https://github.com/secret-scanner/secret-scanner/discussions
