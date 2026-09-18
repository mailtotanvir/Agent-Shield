from datetime import UTC, datetime, timedelta

import pytest

from agentshield.authz.policy import DelegationPolicy, DelegationRules, SensitivityPolicy
from agentshield.errors import PolicyDeniedError
from agentshield.models import TokenClaims, TokenExchangeRequest


def claims(*, scopes: frozenset[str], audience: tuple[str, ...] = ("source",)) -> TokenClaims:
    now = datetime.now(UTC)
    return TokenClaims(
        issuer="https://issuer.example",
        subject="user-1",
        audience=audience,
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
        scopes=scopes,
    )


def test_delegation_scope_is_intersection_only() -> None:
    subject = claims(scopes=frozenset({"read"}))
    request = TokenExchangeRequest(
        subject_token="opaque",
        audience="downstream",
        scopes=frozenset({"read", "admin"}),
    )
    policy = DelegationPolicy(
        DelegationRules(
            allowed_scopes=frozenset({"read", "admin"}),
            allowed_audiences=frozenset({"downstream"}),
        )
    )
    with pytest.raises(PolicyDeniedError, match="subject"):
        policy.authorize_request(subject, request)


def test_result_cannot_extend_subject_lifetime() -> None:
    now = datetime.now(UTC)
    subject = claims(scopes=frozenset({"read"}))
    request = TokenExchangeRequest(
        subject_token="opaque", audience="downstream", scopes=frozenset({"read"})
    )
    result = TokenClaims(
        issuer="https://issuer.example",
        subject="user-1",
        audience=("downstream",),
        issued_at=now,
        expires_at=subject.expires_at + timedelta(seconds=1),
        scopes=frozenset({"read"}),
    )
    policy = DelegationPolicy(
        DelegationRules(
            allowed_scopes=frozenset({"read"}),
            allowed_audiences=frozenset({"downstream"}),
        )
    )
    policy.authorize_request(subject, request)
    with pytest.raises(PolicyDeniedError, match="lifetime"):
        policy.validate_result(subject, result, request, now=now)


def test_sensitive_actions_require_proof() -> None:
    policy = SensitivityPolicy(proof_required_scopes=frozenset({"records.read"}))
    assert policy.requires_proof(scopes=frozenset(), action="delete")
    assert policy.requires_proof(scopes=frozenset({"records.read"}), action="read")
    assert not policy.requires_proof(scopes=frozenset({"public.read"}), action="read")


@pytest.mark.parametrize(
    ("exchange_request", "message"),
    [
        (
            TokenExchangeRequest(subject_token="x", scopes=frozenset({"read"})),
            "audience or resource",
        ),
        (
            TokenExchangeRequest(
                subject_token="x", audience="wrong", scopes=frozenset({"read"})
            ),
            "audience",
        ),
        (
            TokenExchangeRequest(
                subject_token="x", resource="wrong", scopes=frozenset({"read"})
            ),
            "resource",
        ),
    ],
)
def test_delegation_rejects_unapproved_targets(
    exchange_request: TokenExchangeRequest, message: str
) -> None:
    policy = DelegationPolicy(
        DelegationRules(
            allowed_scopes=frozenset({"read"}),
            allowed_audiences=frozenset({"api"}),
            allowed_resources=frozenset({"https://resource.example"}),
        )
    )
    with pytest.raises(PolicyDeniedError, match=message):
        policy.authorize_request(claims(scopes=frozenset({"read"})), exchange_request)
