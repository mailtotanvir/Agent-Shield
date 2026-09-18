"""Pre- and post-conditions for externally issued RFC 8693 tokens."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from agentshield.errors import PolicyDeniedError
from agentshield.models import TokenClaims, TokenExchangeRequest


class DelegationRules(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_scopes: frozenset[str]
    allowed_audiences: frozenset[str] = frozenset()
    allowed_resources: frozenset[str] = frozenset()
    max_lifetime_seconds: int = Field(default=900, gt=0, le=3600)
    preserve_subject: bool = True


class DelegationPolicy:
    def __init__(self, rules: DelegationRules) -> None:
        self.rules = rules

    def authorize_request(self, subject: TokenClaims, request: TokenExchangeRequest) -> None:
        if subject.is_expired():
            raise PolicyDeniedError("subject token is expired")
        if not request.scopes.issubset(subject.scopes):
            raise PolicyDeniedError("requested scope exceeds subject token")
        if not request.scopes.issubset(self.rules.allowed_scopes):
            raise PolicyDeniedError("requested scope exceeds agent policy")
        if request.audience and request.audience not in self.rules.allowed_audiences:
            raise PolicyDeniedError("requested audience is not allowed")
        if request.resource and request.resource not in self.rules.allowed_resources:
            raise PolicyDeniedError("requested resource is not allowed")
        if request.audience is None and request.resource is None:
            raise PolicyDeniedError("token exchange requires an audience or resource")

    def validate_result(
        self,
        subject: TokenClaims,
        result: TokenClaims,
        request: TokenExchangeRequest,
        *,
        now: datetime | None = None,
    ) -> None:
        current = now or datetime.now(UTC)
        if self.rules.preserve_subject and result.subject != subject.subject:
            raise PolicyDeniedError("exchanged token changed subject")
        if not request.scopes.issubset(result.scopes):
            raise PolicyDeniedError("exchanged token omits requested scope")
        if not result.scopes.issubset(subject.scopes & self.rules.allowed_scopes):
            raise PolicyDeniedError("exchanged token contains escalated scope")
        expected_audience = request.audience or request.resource
        if expected_audience not in result.audience:
            raise PolicyDeniedError("exchanged token has unexpected audience")
        maximum_expiry = min(
            subject.expires_at,
            current + timedelta(seconds=self.rules.max_lifetime_seconds),
        )
        if result.expires_at > maximum_expiry:
            raise PolicyDeniedError("exchanged token extends effective lifetime")


class SensitivityPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    proof_required_scopes: frozenset[str] = frozenset()
    proof_required_actions: frozenset[str] = frozenset(
        {"write", "delete", "admin", "payment", "identity", "token", "credential", "secret"}
    )

    def requires_proof(
        self,
        *,
        scopes: frozenset[str],
        action: str,
        sensitivity: str | None = None,
    ) -> bool:
        return (
            sensitivity == "high"
            or bool(scopes & self.proof_required_scopes)
            or action.lower() in self.proof_required_actions
        )

