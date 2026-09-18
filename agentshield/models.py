"""Shared, immutable domain models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PKCEVerifier(FrozenModel):
    value: str = Field(min_length=43, max_length=128, pattern=r"^[A-Za-z0-9._~-]+$")


class AuthorizationRequest(FrozenModel):
    scopes: tuple[str, ...]
    redirect_uri: HttpUrl
    state: str = Field(min_length=16, max_length=512)
    nonce: str = Field(min_length=16, max_length=512)
    pkce_verifier: PKCEVerifier


class CodeExchangeRequest(FrozenModel):
    code: str = Field(min_length=1, max_length=8192)
    redirect_uri: HttpUrl
    pkce_verifier: PKCEVerifier


class TokenSet(FrozenModel):
    access_token: str = Field(min_length=1)
    token_type: str
    expires_in: int = Field(gt=0)
    refresh_token: str | None = None
    id_token: str | None = None
    scope: tuple[str, ...] = ()

    @field_validator("token_type")
    @classmethod
    def normalize_token_type(cls, value: str) -> str:
        if value.lower() not in {"bearer", "dpop"}:
            raise ValueError("unsupported token type")
        return value.lower()


class TokenClaims(FrozenModel):
    issuer: str
    subject: str
    audience: tuple[str, ...]
    expires_at: datetime
    issued_at: datetime
    not_before: datetime | None = None
    jwt_id: str | None = None
    scopes: frozenset[str] = frozenset()
    confirmation_jkt: str | None = None
    actor: dict[str, Any] | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("expires_at", "issued_at", "not_before")
    @classmethod
    def require_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return value

    def is_expired(self, *, now: datetime | None = None) -> bool:
        return self.expires_at <= (now or datetime.now(UTC))


class Session(FrozenModel):
    session_id: str
    access_token: str
    token_type: str
    expires_at: datetime
    scopes: frozenset[str]


class TokenExchangeRequest(FrozenModel):
    subject_token: str = Field(min_length=1)
    subject_token_type: str = (
        "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 -- identifier
    )
    requested_token_type: str = (
        "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 -- identifier
    )
    audience: str | None = None
    resource: str | None = None
    scopes: frozenset[str] = frozenset()
