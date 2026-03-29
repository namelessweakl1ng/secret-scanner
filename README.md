# 🔐 Secret Scanner CLI

A fast, lightweight CLI tool to detect hardcoded secrets in codebases using:

* 🔍 Regex-based detection
* 🧠 Entropy analysis
* 📊 Context-aware scoring
* ⚡ Parallel file scanning

---

## 🚀 Features

* Detects API keys, tokens, passwords
* Supports custom rules via YAML
* Git integration:

  * Scan full history
  * Scan diffs
  * Scan staged files
* GitHub Actions support (PR annotations)
* Pre-commit hook support
* JSON / Table / CLI output

---

## 📦 Installation

```bash
go install github.com/namelessweakl1ng/secret-scanner@latest
```

---

## ⚡ Usage

### Scan directory

```bash
secret-scanner scan .
```

### Scan staged files

```bash
secret-scanner scan . --staged
```

### Scan git history

```bash
secret-scanner scan . --git
```

### JSON output

```bash
secret-scanner scan . --json
```

---

## 🔧 Configuration

Rules are defined in:

```
rules/rules.yaml
```

Example:

```yaml
rules:
  - name: github_token
    pattern: ghp_[a-zA-Z0-9]{36}
    severity: HIGH
```

---

## 🛠 GitHub Actions

This project supports GitHub annotations:

```yaml
- run: secret-scanner scan . --github
```

---

## 🧠 How It Works

The scanner combines:

* Regex pattern matching
* Shannon entropy calculation
* Context keyword scoring
* Validation (AWS keys, JWT)

---

## 📌 Exit Codes

* `0` → No issues
* `1` → Secrets found
* `2` → Error

---

## 📜 License

MIT
