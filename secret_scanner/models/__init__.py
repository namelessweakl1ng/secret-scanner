"""Core data models for secret scanner findings.

These models are the contract between every layer of the system:
detectors produce Findings, scanners aggregate them into ScanResults,
and reporters serialize them to disk.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(IntEnum):
    """Severity of a detected secret.

    Ordered from least to most severe so that ``max(severities)`` gives the
    dominant severity of a scan. The integer values are also used as the
    process exit code when ``--fail-on`` is configured.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        """Parse a severity from a case-insensitive string."""
        if isinstance(value, Severity):
            return value
        v = value.strip().upper()
        try:
            return cls[v]
        except KeyError as exc:
            raise ValueError(f"Unknown severity: {value!r}") from exc

    @property
    def label(self) -> str:
        """Human-readable label."""
        return self.name.title()

    @property
    def rich_style(self) -> str:
        """Rich console style for this severity."""
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }[self]


class DetectionMethod(str):
    """How a secret was detected: ``regex``, ``entropy``, ``context``, ``path``."""

    REGEX = "regex"
    ENTROPY = "entropy"
    CONTEXT = "context"
    PATH = "path"
    ARCHIVE = "archive"


class Finding(BaseModel):
    """A single detected secret.

    Findings are immutable records. The :attr:`fingerprint` field is a stable
    SHA-256 hash of the secret value (not the secret itself) so that findings
    can be stored, deduplicated, and compared across scans without ever
    persisting plaintext credentials.
    """

    rule_id: str = Field(..., description="Identifier of the rule that matched.")
    rule_name: str = Field(..., description="Human-readable rule name.")
    provider: str = Field(default="generic", description="Secret provider / category.")
    severity: Severity = Field(..., description="Severity of the finding.")
    confidence: int = Field(..., ge=0, le=100, description="Confidence score 0-100.")
    file_path: str = Field(..., description="Path to the file containing the secret.")
    line_number: int = Field(..., ge=1, description="1-indexed line number.")
    column_start: int = Field(default=1, ge=1)
    column_end: int = Field(default=1, ge=1)
    matched_value: str = Field(..., description="The full matched secret value.")
    masked_value: str = Field(default="", description="Masked representation for display.")
    context_line: str = Field(
        default="", description="The full line of text where the match occurred."
    )
    detected_by: str = Field(default=DetectionMethod.REGEX, description="Detection method.")
    entropy: float = Field(default=0.0, description="Shannon entropy of the matched value.")
    context_score: int = Field(default=0, ge=0, description="Context boost score.")
    commit_sha: str | None = Field(default=None, description="Git commit SHA if from history.")
    commit_author: str | None = Field(default=None, description="Author of the introducing commit.")
    commit_date: datetime | None = Field(
        default=None, description="Date of the introducing commit."
    )
    explanation: list[str] = Field(
        default_factory=list, description="Reasons contributing to the confidence score."
    )
    recommendation: str = Field(default="", description="Remediation recommendation.")
    fingerprint: str = Field(default="", description="SHA-256 fingerprint of the secret.")

    model_config = {"use_enum_values": False}

    @model_validator(mode="after")
    def _compute_derived(self) -> Finding:
        """Compute fingerprint, mask, and recommendation after validation."""
        if not self.masked_value:
            self.masked_value = mask_secret(self.matched_value)
        if not self.fingerprint:
            self.fingerprint = fingerprint_secret(self.matched_value)
        if not self.recommendation:
            self.recommendation = default_recommendation(self.provider, self.severity)
        return self

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, v: Any) -> Any:
        if isinstance(v, str):
            return Severity.parse(v)
        return v

    def to_sarif(self) -> dict[str, Any]:
        """Convert to a SARIF result object."""
        return {
            "ruleId": self.rule_id,
            "level": _sarif_level(self.severity),
            "message": {
                "text": f"{self.rule_name} detected in {self.file_path}:{self.line_number}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.file_path},
                        "region": {
                            "startLine": self.line_number,
                            "startColumn": self.column_start,
                            "endColumn": self.column_end,
                        },
                    }
                }
            ],
            "partialFingerprints": {"primaryLocationLineHash": self.fingerprint[:16]},
            "properties": {
                "severity": self.severity.label,
                "confidence": self.confidence,
                "provider": self.provider,
                "masked_value": self.masked_value,
                "recommendation": self.recommendation,
                "commit": self.commit_sha,
            },
        }


class ScanResult(BaseModel):
    """The aggregate result of a scan.

    Holds all findings from a single scan invocation plus metadata about the
    scan itself (target, duration, files scanned).
    """

    target: str = Field(..., description="What was scanned (path/URL).")
    scan_type: str = Field(..., description="Type of scan (local/git/github/...).")
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    scanner_version: str = "1.0.0"

    @property
    def duration_seconds(self) -> float:
        """Elapsed scan time in seconds."""
        end = self.finished_at or datetime.now(UTC)
        return (end - self.started_at).total_seconds()

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def unique_secrets(self) -> int:
        return len({f.fingerprint for f in self.findings})

    @property
    def dominant_severity(self) -> Severity:
        """Highest severity among findings, or INFO if none."""
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    def severity_counts(self) -> dict[str, int]:
        """Count findings by severity label."""
        counts: dict[str, int] = {s.label: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    def risk_score(self) -> int:
        """Compute a repository risk score 0-100.

        Weighted sum: critical findings dominate, with diminishing returns
        for additional findings of the same severity (logarithmic scaling)
        so that a single huge leak isn't drowned out by hundreds of low-sev.
        """
        import math

        if not self.findings:
            return 0
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        per_sev: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for f in self.findings:
            per_sev[f.severity] += 1
        score = 0.0
        for sev, count in per_sev.items():
            if count == 0:
                continue
            score += weights[sev] * (1 + math.log10(count))
        return min(100, int(score))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SENSITIVE_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|auth|bearer|credential|"
    r"private|jwt|cookie|session|refresh|access|client[_-]?secret)"
)


def mask_secret(value: str, visible_prefix: int = 4, visible_suffix: int = 4) -> str:
    """Mask a secret, keeping only the first/last few characters.

    Examples:
        ``mask_secret("AKIA_example_placeholderER0")`` -> ``"AKIA****************ACE"``
        ``mask_secret("sk-abc123")`` -> ``"sk-****"``
    """
    if not value:
        return ""
    if len(value) <= visible_prefix + visible_suffix:
        return "*" * len(value)
    prefix = value[:visible_prefix]
    suffix = value[-visible_suffix:]
    return f"{prefix}{'*' * 16}{suffix}"


def fingerprint_secret(value: str) -> str:
    """Compute a stable SHA-256 fingerprint of a secret value.

    The fingerprint is salted with a fixed domain-separation string so that
    it cannot be reversed via rainbow tables for short secrets, while still
    being deterministic across scans (for deduplication and baselining).
    """
    salt = b"secret-scanner:v1:"
    return hashlib.sha256(salt + value.encode("utf-8", errors="replace")).hexdigest()


def default_recommendation(provider: str, severity: Severity) -> str:
    """Default remediation recommendation for a provider/severity combo."""
    p = provider.lower()
    if (
        "private_key" in p
        or "private key" in p
        or p in {"ssh_private_key", "rsa_private_key", "pem"}
    ):
        return "Rotate the key immediately, revoke access, audit logs for misuse, and never commit key files."
    if "aws" in p:
        return "Rotate the AWS credential in IAM, revoke active keys, and review CloudTrail for misuse."
    if "github" in p:
        return "Revoke the token at https://github.com/settings/tokens and rotate any dependent CI secrets."
    if "gitlab" in p:
        return "Revoke the token at https://gitlab.com/-/profile/personal_access_tokens."
    if "openai" in p or "anthropic" in p:
        return "Revoke the API key in the provider dashboard and audit usage billing."
    if "database" in p or "mongo" in p or "postgres" in p or "mysql" in p or "redis" in p:
        return "Rotate the database password, restrict network access, and audit recent queries."
    if severity >= Severity.HIGH:
        return "Rotate the credential immediately, revoke existing sessions, and audit access logs."
    if severity >= Severity.MEDIUM:
        return "Investigate the finding; rotate the credential if it is live and remove it from the repo."
    return "Review the finding and remove the secret from version control if sensitive."


def is_sensitive_variable_name(name: str) -> bool:
    """Return True if a variable name looks security-sensitive."""
    return bool(_SENSITIVE_RE.search(name))


def _sarif_level(severity: Severity) -> str:
    """Map severity to SARIF level."""
    if severity >= Severity.HIGH:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


__all__ = [
    "Severity",
    "DetectionMethod",
    "Finding",
    "ScanResult",
    "mask_secret",
    "fingerprint_secret",
    "default_recommendation",
    "is_sensitive_variable_name",
]
