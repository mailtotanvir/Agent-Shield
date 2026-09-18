"""Fail-safe structured-data redaction."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any

SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "authorization",
        "client_secret",
        "code",
        "cookie",
        "id_token",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "set-cookie",
        "token",
    }
)
PII_KEYS = frozenset({"email", "name", "sub", "subject"})
BEARER_PATTERN = re.compile(r"(?i)\b(Bearer|DPoP)\s+[A-Za-z0-9._~+\-/]+=*")


def fingerprint(value: str, *, length: int = 16) -> str:
    """Return a non-reversible correlation fingerprint."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def redact(value: Any, *, key: str | None = None) -> Any:
    """Recursively redact secrets and fingerprint common identity claims."""

    normalized = key.lower().replace("-", "_") if key else None
    if normalized in SENSITIVE_KEYS:
        return "[REDACTED]"
    if normalized in PII_KEYS and isinstance(value, str):
        return f"sha256:{fingerprint(value)}"
    if isinstance(value, Mapping):
        return {str(k): redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return BEARER_PATTERN.sub(lambda m: f"{m.group(1)} [REDACTED]", value)
    return value

