"""Tests for the detection engine.

All test secrets use runtime string construction (via ``SAMPLES`` or
``_s()``) so that no literal real-format secret pattern appears in the
source file. This prevents GitHub Push Protection from blocking the push.
"""

from __future__ import annotations

from secret_scanner.detectors import (
    Engine,
    ScanContext,
    is_base64_like,
    is_hex_like,
    shannon_entropy,
)
from secret_scanner.models import Severity
from secret_scanner.rules import load_default_ruleset

from .samples import SAMPLES


def make_engine(**kwargs) -> Engine:  # noqa: ANN001
    rs = load_default_ruleset()
    return Engine(rs, **kwargs)


# A high-entropy string that doesn't match any provider pattern (used for
# entropy-only tests). Built at runtime to avoid committing a suspicious
# literal.
_ENTROPY_TOKEN = (
    "ZQzq" + "M4Lm" + "Pn2x" + "Kb8r" + "Yw8o" + "U5iV" + "9dF3" + "gH7j" + "K0lP" + "6sN2" + "t"
)


class TestEntropy:
    def test_constant_string_zero(self) -> None:
        assert shannon_entropy("aaaa") == 0.0

    def test_two_chars(self) -> None:
        assert abs(shannon_entropy("ab") - 1.0) < 1e-9

    def test_four_distinct(self) -> None:
        assert abs(shannon_entropy("abcd") - 2.0) < 1e-9

    def test_empty(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_high_entropy_random(self) -> None:
        assert shannon_entropy(_ENTROPY_TOKEN) > 3.5

    def test_is_base64_like(self) -> None:
        assert is_base64_like("dGhpcyBpcyBhIHRlc3Q=")
        assert not is_base64_like("short")

    def test_is_hex_like(self) -> None:
        assert is_hex_like("0123456789abcdef0123456789abcdef")
        assert not is_hex_like("xyz")


class TestRegexDetection:
    def test_aws_access_key(self) -> None:
        eng = make_engine()
        line = f'AWS_KEY = "{SAMPLES["aws_access_key_id"]}"'
        ctx = ScanContext(file_path="config.py", line_number=1, line_text=line)
        findings = eng.scan_line(line, ctx)
        assert any(f.rule_id == "aws_access_key_id" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_github_pat(self) -> None:
        eng = make_engine()
        line = f'GITHUB_TOKEN = "{SAMPLES["github_pat"]}"'
        ctx = ScanContext(file_path="config.py", line_number=1, line_text=line)
        findings = eng.scan_line(line, ctx)
        assert any("github" in f.rule_id for f in findings)

    def test_openai_key(self) -> None:
        eng = make_engine()
        line = f'OPENAI_KEY = "{SAMPLES["openai_key_short"]}"'
        ctx = ScanContext(file_path="config.py", line_number=1, line_text=line)
        findings = eng.scan_line(line, ctx)
        assert any("openai" in f.rule_id for f in findings)

    def test_stripe_key(self) -> None:
        eng = make_engine()
        line = f'STRIPE = "{SAMPLES["stripe_secret"]}"'
        ctx = ScanContext(file_path="config.py", line_number=1, line_text=line)
        findings = eng.scan_line(line, ctx)
        assert any("stripe" in f.rule_id for f in findings)

    def test_private_key_pem(self) -> None:
        eng = make_engine()
        # PEM header is a detection pattern, not a real key. Safe to use as-is.
        line = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
        ctx = ScanContext(file_path="id_rsa", line_number=1, line_text=line)
        findings = eng.scan_line(line, ctx)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_jwt_token(self) -> None:
        eng = make_engine()
        # JWT structure (header.payload.signature). Built at runtime.
        header = "eyJhbGciOiJIUzI1NiJ9"
        payload = "eyJzdWIiOiIxIn0"
        signature = "abc123def456ghi789"
        line = f'token = "{header}.{payload}.{signature}"'
        ctx = ScanContext(file_path="auth.py", line_number=1, line_text=line)
        findings = eng.scan_line(line, ctx)
        assert any(f.rule_id == "jwt_token" for f in findings)

    def test_slack_token(self) -> None:
        eng = make_engine()
        line = f'SLACK = "{SAMPLES["slack_token"]}"'
        ctx = ScanContext(file_path="config.py", line_number=1, line_text=line)
        findings = eng.scan_line(line, ctx)
        assert any("slack" in f.rule_id for f in findings)


class TestEntropyDetection:
    def test_high_entropy_string_caught(self) -> None:
        eng = make_engine(min_entropy=4.0)
        line = f'KEY = "{_ENTROPY_TOKEN}"'
        ctx = ScanContext(file_path="config.py", line_number=1, line_text=line)
        findings = eng.scan_line(line, ctx)
        entropy_findings = [f for f in findings if f.detected_by == "entropy"]
        assert len(entropy_findings) >= 1

    def test_low_entropy_not_caught(self) -> None:
        eng = make_engine(min_entropy=4.5)
        # All same chars - zero entropy.
        line = 'KEY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
        ctx = ScanContext(file_path="config.py", line_number=1, line_text=line)
        findings = eng.scan_line(line, ctx)
        entropy_findings = [f for f in findings if f.detected_by == "entropy"]
        assert len(entropy_findings) == 0

    def test_no_duplicate_entropy_findings(self) -> None:
        eng = make_engine(min_entropy=4.0)
        line = f'TOKEN = "{_ENTROPY_TOKEN}"'
        ctx = ScanContext(file_path="config.py", line_number=1, line_text=line)
        findings = eng.scan_line(line, ctx)
        entropy_findings = [f for f in findings if f.detected_by == "entropy"]
        # Each unique token should appear at most once.
        fingerprints = [f.fingerprint for f in entropy_findings]
        assert len(fingerprints) == len(set(fingerprints))


class TestContextDetection:
    def test_password_assignment_caught(self) -> None:
        eng = make_engine()
        line = 'password = "mysecretpassword123"'
        ctx = ScanContext(file_path="app.py", line_number=1, line_text=line)
        findings = eng.scan_line(line, ctx)
        assert any(
            "password" in f.rule_id.lower() or "password" in f.rule_name.lower() for f in findings
        )

    def test_sensitive_context_boosts_confidence(self) -> None:
        eng = make_engine()
        # Same high-entropy string, one with sensitive variable name, one without.
        line_with_ctx = f'api_key = "{_ENTROPY_TOKEN}"'
        line_without_ctx = f'color = "{_ENTROPY_TOKEN}"'
        ctx1 = ScanContext(file_path="a.py", line_number=1, line_text=line_with_ctx)
        ctx2 = ScanContext(file_path="b.py", line_number=1, line_text=line_without_ctx)
        f1 = eng.scan_line(line_with_ctx, ctx1)
        f2 = eng.scan_line(line_without_ctx, ctx2)
        # Both should detect, but the one with sensitive context should have higher confidence.
        e1 = [f for f in f1 if f.detected_by == "entropy"]
        e2 = [f for f in f2 if f.detected_by == "entropy"]
        if e1 and e2:
            assert e1[0].confidence >= e2[0].confidence


class TestPathDetection:
    def test_env_file_detected(self) -> None:
        eng = make_engine()
        findings = eng.scan_file_path(".env")
        assert len(findings) >= 1
        assert any(".env" in f.rule_name for f in findings)

    def test_id_rsa_detected(self) -> None:
        eng = make_engine()
        findings = eng.scan_file_path("/home/user/.ssh/id_rsa")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_aws_credentials_detected(self) -> None:
        eng = make_engine()
        findings = eng.scan_file_path("/root/.aws/credentials")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_benign_path_not_detected(self) -> None:
        eng = make_engine()
        findings = eng.scan_file_path("/usr/src/app/main.py")
        assert len(findings) == 0


class TestScoring:
    def test_exact_format_provider_high_severity(self) -> None:
        eng = make_engine()
        # Use a sensitive variable name to get the context boost.
        line = f'AWS_SECRET_ACCESS_KEY = "{SAMPLES["aws_access_key_id"]}"'
        ctx = ScanContext(file_path="config.py", line_number=1, line_text=line)
        findings = eng.scan_line(line, ctx)
        aws = next(f for f in findings if f.rule_id == "aws_access_key_id")
        assert aws.severity == Severity.CRITICAL
        assert aws.confidence >= 80
        # Should have multiple explanation components.
        assert len(aws.explanation) >= 3
        assert "regex" in aws.explanation[0].lower() or "pattern" in aws.explanation[0].lower()


class TestScanText:
    def test_multiline(self) -> None:
        eng = make_engine()
        text = (
            f'AWS_KEY = "{SAMPLES["aws_access_key_id"]}"\n'
            'password = "mysecretpassword"\n'
            f'KEY = "{_ENTROPY_TOKEN}"\n'
        )
        findings = eng.scan_text(text, "config.py")
        assert len(findings) >= 2

    def test_empty_text(self) -> None:
        eng = make_engine()
        assert eng.scan_text("", "x.py") == []

    def test_long_line_skipped(self) -> None:
        eng = make_engine(max_line_length=100)
        line = "x" * 200
        ctx = ScanContext(file_path="a.py", line_number=1, line_text=line)
        assert eng.scan_line(line, ctx) == []
