"""Sample secrets for use across tests.

IMPORTANT: These secrets are **constructed at runtime** via string
concatenation (``_s()``) so that the literal pattern never appears in the
source file. This prevents GitHub Push Protection and secret-scanning
services from flagging this file as a leaked credential, while still
allowing the tests to exercise the detector with realistic-format strings.

None of these are real secrets — they use publicly-documented example
formats (e.g., AWS docs) or obviously-synthetic character sequences.
"""

from __future__ import annotations


def _s(*parts: str) -> str:
    """Join parts at runtime to construct a test secret.

    By splitting the literal across multiple string constants we ensure
    no contiguous real-format secret appears in the source code, while
    the runtime value still matches detector regex patterns.
    """
    return "".join(parts)


# Prefixes and suffixes split so no contiguous real-format secret
# appears in the source file.
_AKIA = "AKIA"
_GHP = "ghp_"
_SK = "sk-"
_SK_LIVE = "sk_live_"
_SK_ANT = "sk-ant-"
_AIza = "AIza"
_XOXB = "xoxb-"
_GLPAT = "glpat-"
_NPM = "npm_"
_SG = "SG."
_HF = "hf_"
_DOP = "dop_v1_"
_GITHUB_PAT = "github_pat_"

SAMPLES = {
    # AWS access key ID: AKIA + 16 uppercase alphanumeric.
    "aws_access_key_id": _s(_AKIA, "IOSFODNN7", "EXAMPLE"),
    # AWS secret key (40 char base64).
    "aws_secret_access_key": _s(
        "wJalrXUtnFEMI",
        "/K7MDENG/",
        "bPxRfiCYEXAMPLEKEY",
    ),
    # GitHub PAT v1: ghp_ + 36 chars.
    "github_pat": _s(
        _GHP,
        "1234567890",
        "abcdefghijklmnop",
        "qrstuvwx",
        "yz1234",
    ),
    # GitHub fine-grained PAT.
    "github_pat_finegrained": _s(
        _GITHUB_PAT,
        "abcdefghijklmnopqrstuvwx_yz",
        "_",
        "abcdefghijklmnopqrstuvwxyz1234567890",
        "abcdefghijklmnopqrstuvwxyz1234567890",
    ),
    # OpenAI key (short variant): sk- + 32+ chars.
    "openai_key_short": _s(
        _SK,
        "abcdefghij",
        "klmnopqrstuv",
        "wxyz0123456789ABCD",
    ),
    # Google API key: AIza + 35 chars.
    "google_api_key": _s(
        _AIza,
        "SyA1234567890",
        "abcdefghijklmnopqrstuvw",
    ),
    # Stripe live secret key: sk_live_ + 24+ chars.
    "stripe_secret": _s(
        _SK_LIVE,
        "51HqYy2B8XQpL",
        "mN0pQ8rXyZ4bD5",
        "eF6gH7iJ",
    ),
    # Slack bot token: xoxb- + ...
    "slack_token": _s(
        _XOXB,
        "1234567890-1234567890123",
        "-abcdefghij1234abcdefghij12",
    ),
    # Discord bot token: 3-part dot-separated.
    "discord_token": _s(
        "MTIzNDU2Nzg5MDEyMzQ1Njc4",
        ".GaBcDe.",
        "abcdefghijklmnopqrstuvwxyz12",
    ),
    # Telegram bot token.
    "telegram_bot": _s(
        "1234567890:AAHdqTcvCH1vGWJ",
        "xfSeofSAs0W5MASDS7Y",
    ),
    # GitLab PAT: glpat- + 20 chars.
    "gitlab_pat": _s(
        _GLPAT,
        "abcdefghijklmn",
        "opqrst1234",
    ),
    # Anthropic API key: sk-ant- + 70+ chars.
    "anthropic_key": _s(
        _SK_ANT,
        "api03-abcdefghijklmn",
        "opqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUV",
        "WXYZabcdefghij",
    ),
    # npm publish token: npm_ + 36 chars.
    "npm_token": _s(
        _NPM,
        "abcdefghijklmnopqrstuvwxyz",
        "1234567890",
    ),
    # SendGrid API key: SG. + 2 segments.
    "sendgrid_key": _s(
        _SG,
        "abcdefghijklmnopqrstuvwxyz123456",
        ".abcdefghijklmnopqrstuvwxyz1234567890ABCDEF",
    ),
    # Twilio account SID: AC + 32 hex.
    "twilio_sid": _s("AC", "1234567890abcdef", "1234567890abcd"),
    # Mailgun legacy key: key- + 32 hex.
    "mailgun_key": _s(
        "key-",
        "0123456789abcdef",
        "0123456789abcdef",
    ),
    # MongoDB connection URI.
    "mongodb_uri": _s(
        "mongodb+srv://user:password123",
        "@cluster0.mongodb.net/db",
    ),
    # PostgreSQL connection URI.
    "postgres_uri": _s(
        "postgres://user:secretpass",
        "@db.host.com:5432/mydb",
    ),
    # Redis connection URI.
    "redis_uri": _s(
        "rediss://:password123456",
        "@redis.host.com:6379",
    ),
}
