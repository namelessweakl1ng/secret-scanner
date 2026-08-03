# Changelog

All notable changes to Secret Scanner are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-02

### Added
- Initial production release.
- Local file and directory scanner with parallel workers.
- Git history scanner (commits, branches, tags, stashes) with optional
  git-blame attribution.
- Remote scanners for GitHub, GitLab, Bitbucket, and GitHub Gists.
- Archive scanner (ZIP, TAR, GZ, JAR, WAR, APK) with safe extraction
  (ZIP Slip protection) and secure temp file deletion.
- Raw URL scanner for downloading and scanning individual files.
- Detection engine with layered signals:
  - Regex rules (117 built-in patterns across 5 categories).
  - Shannon entropy for high-entropy string detection.
  - Context detection (sensitive variable names).
  - Path-based detection for sensitive filenames (`.env`, `id_rsa`,
    `credentials.json`, `.aws/credentials`, `.terraform.tfstate`, ...).
- Weighted confidence scoring (0-100) with severity classification
  (Critical, High, Medium, Low, Info).
- Six output formats:
  - Rich terminal output with tables, panels, and progress bars.
  - JSON (machine-readable, deterministic).
  - CSV (one row per finding).
  - Markdown (GitHub-rendered report).
  - HTML (self-contained dashboard with Chart.js visualizations).
  - SARIF 2.1.0 (for GitHub Code Scanning, Azure DevOps, VS Code).
- Configuration via `secret-scanner.yaml` with:
  - Custom rule files (YAML, merged with built-ins).
  - Severity overrides per rule ID.
  - Ignore patterns (glob and regex).
  - Detection tuning (entropy threshold, length limits, workers).
- Ignore system supporting `.gitignore`, `.secretignore`, and custom patterns.
- Baseline mode: save current findings and suppress them in future scans.
- SQLite-backed scan history at `~/.cache/secret-scanner/history.db`.
- Git hooks installation (`pre-commit`, `pre-push`).
- Exit codes matching dominant severity (0-4) for CI integration.
- Repository risk score (0-100) based on finding severity and count.
- Secret fingerprinting (SHA-256 with domain separation) for deduplication
  and baselining — plaintext secrets are never persisted.
- Masked output: secrets are always displayed as `XXXX****XXXX`.
- Interactive menu-driven mode (`secret-scanner interactive`).
- Rule listing and filtering (`secret-scanner rules`).
- Comprehensive test suite (188 tests, 74% coverage).
- Documentation: README, Architecture, Contributing, Rule Authoring,
  Plugin Development, CI Integration, Security Policy.
- GitHub Actions workflows for CI (multi-OS, multi-Python), release
  (PyPI trusted publishing), and pre-commit checks.

### Security
- ZIP Slip protection in archive extractor.
- TAR Slip protection with symlink/device file rejection.
- Secure deletion of temp files (overwrite + unlink).
- ReDoS mitigation via pre-compiled regex and line length limits.
- No command injection (no shell invocation with user input).
- Offline mode for local scans (no network access).
- Plaintext secrets never persisted (only SHA-256 fingerprints).

### Supported Providers
- Cloud: AWS, Azure, GCP, DigitalOcean, Cloudflare, Linode, Scaleway.
- VCS: GitHub (PAT v1/v2, OAuth, fine-grained, runner, pipeline),
  GitLab (PAT, deploy, runner, trigger), Bitbucket.
- AI: OpenAI, Anthropic, Google Gemini, HuggingFace, Replicate.
- Payments: Stripe, PayPal, Square, Braintree, Binance, Coinbase.
- Web3: Alchemy, Infura, QuickNode, Ethereum, Solana, Bitcoin WIF,
  BIP39 mnemonics.
- Communications: Discord, Slack, Telegram, Twilio, Mailgun, SendGrid,
  Mailchimp, Postmark.
- SaaS: npm, Figma, Datadog, Sentry, Notion, Asana, Linear, Jira.
- Crypto: RSA, EC, OpenSSH, DSA, PGP, PKCS8, OpenVPN, WireGuard.
- Database: PostgreSQL, MySQL, MongoDB, Redis, AMQP, Oracle, JDBC.
- Frameworks: Django, Flask, Rails, Laravel, ASP.NET, Spring Boot.
- Generic: JWT, Bearer tokens, OAuth, basic auth, passwords, secrets,
  private keys, certificates, refresh/access tokens, webhook secrets.
