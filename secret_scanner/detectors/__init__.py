"""Secret detection engine.

The engine is the heart of the scanner. It is intentionally pure: given a
chunk of text and the surrounding context (file path, line number, variable
name), it returns a list of :class:`~secret_scanner.models.Finding` objects.

The engine layers four signals:

1. **Regex rules** -- hundreds of provider-specific patterns loaded from YAML.
2. **Entropy** -- Shannon entropy to catch high-entropy random strings
   (base64, hex, JWT segments) that don't match any known pattern.
3. **Context** -- variable names, key names, and file paths that look
   security-sensitive boost the confidence of nearby matches.
4. **Path** -- sensitive file names (``.env``, ``id_rsa``, ``credentials.json``)
   are findings on their own.

A weighted scoring formula combines these signals into a 0-100 confidence
score and a severity. The formula is deterministic and fully explained in
the :class:`Engine` docstring.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from ..models import (
    DetectionMethod,
    Finding,
    Severity,
    default_recommendation,
    is_sensitive_variable_name,
)
from ..rules.loader import Rule, RuleSet

# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy (bits per symbol) of a string.

    Examples:
        >>> shannon_entropy("aaaa")
        0.0
        >>> shannon_entropy("abcd")
        2.0
        >>> 4.0 < shannon_entropy("ZQzqM4LmPn2xKb8r") < 5.0
        True
    """
    if not data:
        return 0.0
    counts: dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_base64_like(s: str) -> bool:
    """Heuristic: does this look like base64-encoded data?"""
    if len(s) < 16:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s))


def is_hex_like(s: str) -> bool:
    """Heuristic: does this look like a hex string?"""
    if len(s) < 16 or len(s) % 2 != 0:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


@dataclass
class ScoreComponents:
    """The individual signals that feed into the confidence score."""

    regex_match: bool = False
    entropy: float = 0.0
    high_entropy: bool = False
    sensitive_context: bool = False
    sensitive_path: bool = False
    known_provider: bool = False
    min_length_ok: bool = False
    exact_format_match: bool = False
    reasons: list[str] = field(default_factory=list)

    def score(self) -> tuple[int, list[str]]:
        """Return (confidence 0-100, explanation list)."""
        score = 0
        reasons: list[str] = []

        if self.regex_match:
            score += 40
            reasons.append("Matched known regex pattern")
        if self.exact_format_match:
            score += 15
            reasons.append("Exact provider format match")
        if self.known_provider:
            score += 10
            reasons.append("Known provider")
        if self.high_entropy:
            score += 15
            reasons.append(f"High Shannon entropy ({self.entropy:.2f} bits/symbol)")
        elif self.entropy > 3.5:
            score += 5
            reasons.append(f"Moderate entropy ({self.entropy:.2f})")
        if self.sensitive_context:
            score += 15
            reasons.append("Sensitive variable/key name nearby")
        if self.sensitive_path:
            score += 10
            reasons.append("Sensitive file path")
        if self.min_length_ok:
            score += 5
            reasons.append("Length consistent with a real secret")

        return min(100, score), reasons


def severity_from_confidence(provider: str, confidence: int, exact_format: bool) -> Severity:
    """Map (provider, confidence, exact_format) -> Severity.

    Critical: known provider, exact format, very high confidence
        - AWS keys, private keys, GitHub PATs, OpenAI keys, seed phrases
    High:   high confidence or known provider with high confidence
        - JWT secrets, bearer tokens, webhook secrets, OAuth
    Medium: medium confidence
        - Password-like strings, unknown tokens
    Low:    low confidence (suspicious entropy)
    Info:   very low confidence (potential sensitive config)
    """
    critical_providers = {
        "aws_access_key",
        "aws_secret_key",
        "private_key",
        "ssh_private_key",
        "rsa_private_key",
        "ecdsa_private_key",
        "ed25519_private_key",
        "pgp_private_key",
        "github_pat",
        "openai_api_key",
        "anthropic_api_key",
        "seed_phrase",
        "mnemonic",
        "ethereum_private_key",
        "bitcoin_wif",
        "production_password",
        "database_password",
    }
    high_providers = {
        "jwt_secret",
        "bearer_token",
        "webhook_secret",
        "oauth_secret",
        "client_secret",
        "gitlab_pat",
        "bitbucket_app_password",
        "stripe_secret_key",
        "google_api_key",
        "firebase_web_api_key",
    }

    p = provider.lower()
    if p in critical_providers and exact_format and confidence >= 70:
        return Severity.CRITICAL
    if p in critical_providers and confidence >= 60:
        return Severity.HIGH
    if p in high_providers and confidence >= 60:
        return Severity.HIGH
    if confidence >= 70:
        return Severity.HIGH
    if confidence >= 50:
        return Severity.MEDIUM
    if confidence >= 30:
        return Severity.LOW
    return Severity.INFO


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


@dataclass
class ScanContext:
    """Context for a single line/file being scanned."""

    file_path: str
    line_number: int = 1
    line_text: str = ""
    full_text: str = ""
    is_binary: bool = False
    file_extension: str = ""


class Engine:
    """The detection engine.

    Usage::

        rules = RuleSet.load_default()
        engine = Engine(rules, min_entropy=4.5, min_length=12)
        findings = engine.scan_line("api_key = 'sk-abc123...'", ctx)

    The engine is **stateless** between calls; thread-safe for parallel scans.
    """

    # Tunables (also overridable from config).
    DEFAULT_MIN_ENTROPY: float = 4.5
    DEFAULT_MIN_LENGTH: int = 12
    DEFAULT_MAX_LENGTH: int = 4096
    DEFAULT_MAX_LINE_LENGTH: int = 100_000

    # Sensitive file names / patterns that are findings on their own.
    SENSITIVE_PATH_PATTERNS: tuple[tuple[str, str, Severity], ...] = (
        (r"(^|/)\.env$", ".env file", Severity.HIGH),
        (
            r"(^|/)\.env\.(local|production|development|staging|prod|dev)$",
            ".env variant",
            Severity.HIGH,
        ),
        (r"(^|/)id_rsa$", "SSH private key file", Severity.CRITICAL),
        (r"(^|/)id_ed25519$", "SSH private key file", Severity.CRITICAL),
        (r"(^|/)id_ecdsa$", "SSH private key file", Severity.CRITICAL),
        (r"(^|/)id_dsa$", "SSH private key file", Severity.CRITICAL),
        (r"\.pem$", "PEM certificate/key file", Severity.CRITICAL),
        (r"\.key$", "Private key file", Severity.CRITICAL),
        (r"\.p12$", "PKCS12 keychain file", Severity.HIGH),
        (r"\.pfx$", "PFX certificate file", Severity.HIGH),
        (r"(^|/)\.kube/config$", "Kubernetes config file", Severity.HIGH),
        (r"(^|/)\.npmrc$", ".npmrc (may contain auth token)", Severity.MEDIUM),
        (r"(^|/)\.pypirc$", ".pypirc (may contain password)", Severity.MEDIUM),
        (r"(^|/)\.netrc$", ".netrc (may contain password)", Severity.HIGH),
        (
            r"(^|/)\.docker/config\.json$",
            "Docker config (may contain registry creds)",
            Severity.HIGH,
        ),
        (r"(^|/)\.aws/credentials$", "AWS credentials file", Severity.CRITICAL),
        (r"(^|/)\.aws/config$", "AWS config file", Severity.MEDIUM),
        (r"\.terraform\.tfstate$", "Terraform state (may contain secrets)", Severity.HIGH),
        (r"(^|/)credentials\.json$", "GCP/credentials JSON", Severity.CRITICAL),
        (r"(^|/)service_account\.json$", "GCP service account", Severity.CRITICAL),
        (r"(^|/)secrets\.yml$", "Secrets YAML", Severity.HIGH),
        (r"(^|/)secrets\.yaml$", "Secrets YAML", Severity.HIGH),
    )

    def __init__(
        self,
        rules: RuleSet,
        *,
        min_entropy: float | None = None,
        min_length: int | None = None,
        max_length: int | None = None,
        max_line_length: int | None = None,
        enable_entropy: bool = True,
        enable_context: bool = True,
        enable_path_rules: bool = True,
        entropy_min_length: int = 20,
    ) -> None:
        self.rules = rules
        self.min_entropy = min_entropy if min_entropy is not None else self.DEFAULT_MIN_ENTROPY
        self.min_length = min_length if min_length is not None else self.DEFAULT_MIN_LENGTH
        self.max_length = max_length if max_length is not None else self.DEFAULT_MAX_LENGTH
        self.max_line_length = (
            max_line_length if max_line_length is not None else self.DEFAULT_MAX_LINE_LENGTH
        )
        self.enable_entropy = enable_entropy
        self.enable_context = enable_context
        self.enable_path_rules = enable_path_rules
        self.entropy_min_length = entropy_min_length

        # Pre-compile sensitive path patterns.
        self._compiled_sensitive_paths: list[tuple[re.Pattern[str], str, Severity]] = [
            (re.compile(p), name, sev) for p, name, sev in self.SENSITIVE_PATH_PATTERNS
        ]

        # Pattern for extracting "key = value" or "key: value" pairs to find
        # the variable name near a match (for context scoring).
        self._kv_pattern = re.compile(
            r"""(?P<key>[A-Za-z_][A-Za-z0-9_\-\.]*)\s*[:=]\s*["']?(?P<val>[^"'\s,;}\)\]]+)""",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file_path(self, path: str) -> list[Finding]:
        """Generate findings purely from a file path (sensitive file names)."""
        if not self.enable_path_rules:
            return []
        out: list[Finding] = []
        for pattern, name, severity in self._compiled_sensitive_paths:
            if pattern.search(path):
                out.append(
                    self._make_path_finding(
                        path=path,
                        rule_id=f"path:{name}",
                        rule_name=name,
                        severity=severity,
                    )
                )
        return out

    def scan_line(self, line: str, ctx: ScanContext) -> list[Finding]:
        """Scan a single line of text and return any findings.

        This is the hot path -- it must be fast. We compile all rule regexes
        once (in :class:`RuleSet`) and iterate over them once per line.
        """
        if not line or len(line) > self.max_line_length:
            return []

        findings: list[Finding] = []
        seen_spans: list[tuple[int, int]] = []

        # Phase 1: regex rules. We collect all candidate matches first, then
        # resolve overlaps by preferring the more-specific rule (exact_format
        # beats non-exact; longer match wins; lower rule_id for ties).
        candidates: list[tuple[int, int, Rule, re.Match[str]]] = []
        for rule in self.rules:
            for m in rule.compiled.finditer(line):
                value = m.group(0)
                if len(value) < rule.min_length or len(value) > rule.max_length:
                    continue
                candidates.append((m.start(), m.end(), rule, m))

        # Sort: prefer exact_format, then longer match, then earlier position.
        candidates.sort(key=lambda c: (not c[2].exact_format, -(c[1] - c[0]), c[0]))

        for start, end, rule, m in candidates:
            if self._overlaps_seen(start, end, seen_spans):
                continue
            seen_spans.append((start, end))
            findings.append(self._build_regex_finding(rule, m.group(0), line, start, end, ctx))

        # Phase 2: entropy on tokens that look like high-entropy strings
        if self.enable_entropy:
            seen_entropy_tokens: set[str] = set()
            for tok in self._extract_tokens(line):
                if tok in seen_entropy_tokens:
                    continue
                if len(tok) < max(self.entropy_min_length, self.min_length):
                    continue
                span = self._token_span(line, tok)
                if span == (0, 0) or self._overlaps_seen(span[0], span[1], seen_spans):
                    continue
                ent = shannon_entropy(tok)
                if ent >= self.min_entropy:
                    seen_spans.append(span)
                    seen_entropy_tokens.add(tok)
                    findings.append(self._build_entropy_finding(tok, ent, line, ctx))

        return findings

    def scan_text(self, text: str, file_path: str) -> list[Finding]:
        """Scan a full text blob and return all findings (multi-line aware)."""
        if not text:
            return []
        findings: list[Finding] = []
        # Path-based findings first.
        findings.extend(self.scan_file_path(file_path))

        for i, line in enumerate(text.splitlines(), start=1):
            ctx = ScanContext(
                file_path=file_path,
                line_number=i,
                line_text=line,
                full_text=text,
                file_extension=Path(file_path).suffix,
            )
            findings.extend(self.scan_line(line, ctx))
        return findings

    # ------------------------------------------------------------------
    # Finding builders
    # ------------------------------------------------------------------

    def _build_regex_finding(
        self,
        rule: Rule,
        value: str,
        line: str,
        start: int,
        end: int,
        ctx: ScanContext,
    ) -> Finding:
        """Build a Finding from a regex rule match."""
        ent = shannon_entropy(value)
        high_entropy = ent >= self.min_entropy
        sensitive_ctx = self._has_sensitive_context(line, value)
        sensitive_path = self._is_sensitive_path(ctx.file_path)

        components = ScoreComponents(
            regex_match=True,
            entropy=ent,
            high_entropy=high_entropy,
            sensitive_context=sensitive_ctx,
            sensitive_path=sensitive_path,
            known_provider=rule.provider != "generic",
            min_length_ok=len(value) >= rule.min_length,
            exact_format_match=rule.exact_format,
        )
        confidence, reasons = components.score()
        severity = severity_from_confidence(rule.provider, confidence, rule.exact_format)

        return Finding(
            rule_id=rule.id,
            rule_name=rule.name,
            provider=rule.provider,
            severity=severity,
            confidence=confidence,
            file_path=ctx.file_path,
            line_number=ctx.line_number,
            column_start=start + 1,
            column_end=end + 1,
            matched_value=value,
            context_line=line.strip(),
            detected_by=DetectionMethod.REGEX,
            entropy=ent,
            context_score=15 if sensitive_ctx else 0,
            explanation=reasons,
            recommendation=default_recommendation(rule.provider, severity),
        )

    def _build_entropy_finding(
        self,
        token: str,
        entropy: float,
        line: str,
        ctx: ScanContext,
    ) -> Finding:
        """Build a Finding from a high-entropy token (no regex match)."""
        sensitive_ctx = self._has_sensitive_context(line, token)
        sensitive_path = self._is_sensitive_path(ctx.file_path)

        components = ScoreComponents(
            regex_match=False,
            entropy=entropy,
            high_entropy=True,
            sensitive_context=sensitive_ctx,
            sensitive_path=sensitive_path,
            known_provider=False,
            min_length_ok=len(token) >= self.min_length,
            exact_format_match=False,
        )
        confidence, reasons = components.score()
        severity = severity_from_confidence("generic", confidence, False)

        return Finding(
            rule_id="entropy:high",
            rule_name="High-entropy string",
            provider="generic",
            severity=severity,
            confidence=confidence,
            file_path=ctx.file_path,
            line_number=ctx.line_number,
            column_start=line.find(token) + 1,
            column_end=line.find(token) + len(token) + 1,
            matched_value=token,
            context_line=line.strip(),
            detected_by=DetectionMethod.ENTROPY,
            entropy=entropy,
            context_score=15 if sensitive_ctx else 0,
            explanation=reasons,
            recommendation=default_recommendation("generic", severity),
        )

    def _make_path_finding(
        self,
        path: str,
        rule_id: str,
        rule_name: str,
        severity: Severity,
    ) -> Finding:
        """Build a Finding from a sensitive file path alone."""
        return Finding(
            rule_id=rule_id,
            rule_name=rule_name,
            provider="sensitive_file",
            severity=severity,
            confidence=80,
            file_path=path,
            line_number=1,
            column_start=1,
            column_end=1,
            matched_value=Path(path).name,
            context_line="(file presence)",
            detected_by=DetectionMethod.PATH,
            explanation=["Sensitive file name detected"],
            recommendation=default_recommendation("sensitive_file", severity),
        )

    # ------------------------------------------------------------------
    # Context helpers
    # ------------------------------------------------------------------

    def _has_sensitive_context(self, line: str, value: str) -> bool:
        """Return True if a sensitive variable name appears near ``value``."""
        if not self.enable_context:
            return False
        idx = line.find(value)
        if idx < 0:
            return False
        # Look at the 60 chars before the match for a key name.
        window_start = max(0, idx - 60)
        window = line[window_start : idx + len(value)]
        for m in self._kv_pattern.finditer(window):
            if m.group("val") == value and is_sensitive_variable_name(m.group("key")):
                return True
        # Also check if line itself contains a sensitive keyword.
        return is_sensitive_variable_name(line[: idx + len(value)])

    def _is_sensitive_path(self, path: str) -> bool:
        """Return True if the file path matches a sensitive file pattern."""
        return any(p.search(path) for p, _, _ in self._compiled_sensitive_paths)

    @staticmethod
    def _overlaps_seen(start: int, end: int, seen: list[tuple[int, int]]) -> bool:
        """Return True if [start, end) overlaps any previously seen span."""
        return any(start < e and end > s for s, e in seen)

    @staticmethod
    def _token_span(line: str, token: str) -> tuple[int, int]:
        idx = line.find(token)
        if idx < 0:
            return (0, 0)
        return (idx, idx + len(token))

    @staticmethod
    def _extract_tokens(line: str) -> Iterable[str]:
        """Extract candidate high-entropy tokens from a line.

        We look for:
        - Quoted strings of length >= 20
        - Long base64/hex runs
        - Long alphanumeric runs (potential JWT, opaque tokens)
        """
        # Quoted strings
        for m in re.finditer(r"""["']([A-Za-z0-9+/=_\-\.]{20,})["']""", line):
            yield m.group(1)
        # Bare base64/hex runs
        for m in re.finditer(r"\b[A-Za-z0-9+/=_\-]{32,}\b", line):
            yield m.group(0)
        # JWT-like (three base64 segments)
        for m in re.finditer(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b", line):
            yield m.group(0)


__all__ = [
    "Engine",
    "ScanContext",
    "ScoreComponents",
    "shannon_entropy",
    "is_base64_like",
    "is_hex_like",
    "severity_from_confidence",
]
