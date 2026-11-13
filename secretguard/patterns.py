"""Credential patterns and entropy helpers used by the scanner."""

import math
import re
import string
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    """A named regex that identifies one kind of credential.

    If the regex has a group named ``secret``, only that group is reported
    as the leaked value; otherwise the whole match is.
    """

    name: str
    regex: re.Pattern
    description: str


def _p(name, pattern, description, flags=0):
    return SecretPattern(name, re.compile(pattern, flags), description)


PATTERNS = [
    _p(
        "aws-access-key-id",
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b",
        "AWS access key ID",
    ),
    _p(
        "aws-secret-access-key",
        r"aws_?secret_?(?:access_?)?key\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9/+=]{40})\b",
        "AWS secret access key",
        re.IGNORECASE,
    ),
    _p(
        "private-key-block",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        "PEM / OpenSSH / PGP private key block",
    ),
    _p(
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        "JSON Web Token",
    ),
    _p(
        "github-token",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}",
        "GitHub personal access / OAuth token",
    ),
    _p(
        "slack-token",
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
        "Slack token",
    ),
    _p(
        "google-api-key",
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        "Google API key",
    ),
    _p(
        "stripe-live-key",
        r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}",
        "Stripe live secret key",
    ),
    _p(
        "generic-credential-assignment",
        r"\b(?:\w*_)?(?:password|passwd|pwd|secret|api_?key|access_?token|auth_?token|client_?secret)\b"
        r"[\"']?\s*[:=]\s*[\"'](?P<secret>[^\"'\s]{8,})[\"']",
        "Hardcoded password or key assigned to a credential-like name",
        re.IGNORECASE,
    ),
]

# Candidate tokens for the entropy check: long runs of base64 / hex characters.
ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")

HEX_CHARS = frozenset(string.hexdigits)


def shannon_entropy(text):
    """Return the Shannon entropy of ``text`` in bits per character."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def is_high_entropy(token, threshold=4.5, hex_threshold=3.0):
    """Decide whether ``token`` looks like random key material.

    Hex strings have a lower maximum entropy (4 bits/char), so they use
    their own threshold. Tokens must mix character classes to avoid flagging
    long identifiers such as ``very_long_function_name_here``.
    """
    if set(token) <= HEX_CHARS:
        has_digit = any(c.isdigit() for c in token)
        has_alpha = any(c.isalpha() for c in token)
        return has_digit and has_alpha and shannon_entropy(token) >= hex_threshold
    classes = sum(
        [
            any(c.islower() for c in token),
            any(c.isupper() for c in token),
            any(c.isdigit() for c in token),
        ]
    )
    return classes >= 3 and shannon_entropy(token) >= threshold
