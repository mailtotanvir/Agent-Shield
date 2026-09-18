"""Strict asymmetric JWT validation pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

import jwt
from pydantic import BaseModel, ConfigDict, Field

from agentshield.errors import AlgorithmForbiddenError, TokenValidationError
from agentshield.models import TokenClaims
from agentshield.session.jwks import JWKSCache


class ValidationPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    issuer: str
    audience: str
    allowed_algorithms: tuple[Literal["ES256", "RS256"], ...] = ("ES256", "RS256")
    required_scopes: frozenset[str] = frozenset()
    require_dpop_binding: bool = False
    leeway_seconds: int = Field(default=30, ge=0, le=120)
    max_token_bytes: int = Field(default=16_384, ge=1024, le=65_536)


class JWTValidator:
    def __init__(self, jwks: JWKSCache) -> None:
        self._jwks = jwks

    async def validate(self, token: str, policy: ValidationPolicy) -> TokenClaims:
        if len(token.encode("utf-8")) > policy.max_token_bytes:
            raise TokenValidationError("token exceeds size limit")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenValidationError("token header is malformed") from exc
        algorithm = header.get("alg")
        if algorithm not in policy.allowed_algorithms:
            raise AlgorithmForbiddenError("token algorithm is forbidden")
        if "jku" in header or "x5u" in header:
            raise TokenValidationError("remote key references are forbidden")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenValidationError("token is missing kid")
        key = await self._jwks.resolve(kid, algorithm)
        try:
            payload = jwt.decode(
                token,
                key=key,
                algorithms=list(policy.allowed_algorithms),
                issuer=policy.issuer,
                audience=policy.audience,
                leeway=policy.leeway_seconds,
                options={"require": ["exp", "iat", "iss", "sub", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenValidationError("token validation failed") from exc
        return self._claims(payload, policy)

    @staticmethod
    def _claims(payload: dict[str, Any], policy: ValidationPolicy) -> TokenClaims:
        audience_value = payload["aud"]
        audience = (audience_value,) if isinstance(audience_value, str) else tuple(audience_value)
        scope_value = payload.get("scope", "")
        scopes = frozenset(scope_value.split()) if isinstance(scope_value, str) else frozenset()
        if not policy.required_scopes.issubset(scopes):
            raise TokenValidationError("token lacks required scope")
        cnf = payload.get("cnf")
        jkt = cnf.get("jkt") if isinstance(cnf, dict) and isinstance(cnf.get("jkt"), str) else None
        if policy.require_dpop_binding and jkt is None:
            raise TokenValidationError("token lacks required DPoP binding")
        reserved = {"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "scope", "cnf", "act"}
        return TokenClaims(
            issuer=payload["iss"],
            subject=payload["sub"],
            audience=audience,
            expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
            issued_at=datetime.fromtimestamp(payload["iat"], tz=UTC),
            not_before=(
                datetime.fromtimestamp(payload["nbf"], tz=UTC) if "nbf" in payload else None
            ),
            jwt_id=payload.get("jti"),
            scopes=scopes,
            confirmation_jkt=jkt,
            actor=payload.get("act") if isinstance(payload.get("act"), dict) else None,
            extra={key: value for key, value in payload.items() if key not in reserved},
        )
