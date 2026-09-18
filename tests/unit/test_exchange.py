from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from agentshield.authz.exchange import TokenExchangeClient
from agentshield.authz.policy import DelegationPolicy, DelegationRules
from agentshield.models import TokenClaims, TokenExchangeRequest


class Validator:
    async def validate(self, token: str, policy: object) -> TokenClaims:
        assert token == "signed-access-token"
        now = datetime.now(UTC)
        return TokenClaims(
            issuer="https://issuer.example",
            subject="user-1",
            audience=("downstream",),
            issued_at=now,
            expires_at=now + timedelta(minutes=4),
            scopes=frozenset({"read"}),
        )


@pytest.mark.asyncio
@respx.mock
async def test_token_exchange_applies_pre_and_post_policy() -> None:
    now = datetime.now(UTC)
    subject = TokenClaims(
        issuer="https://issuer.example",
        subject="user-1",
        audience=("source",),
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
        scopes=frozenset({"read", "write"}),
    )
    request = TokenExchangeRequest(
        subject_token="subject-token",
        audience="downstream",
        scopes=frozenset({"read"}),
    )
    policy = DelegationPolicy(
        DelegationRules(
            allowed_scopes=frozenset({"read"}),
            allowed_audiences=frozenset({"downstream"}),
        )
    )
    route = respx.post("https://issuer.example/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "signed-access-token",
                "token_type": "DPoP",
                "expires_in": 240,
                "scope": "read",
            },
        )
    )
    async with TokenExchangeClient(
        "https://issuer.example/token",
        client_id="agent",
        validator=Validator(),  # type: ignore[arg-type]
        issuer="https://issuer.example",
    ) as exchange:
        result = await exchange.exchange(request, subject_claims=subject, policy=policy)
    assert result.token_type == "dpop"
    body = route.calls[0].request.content.decode()
    assert "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" in body
    assert "subject-token" in body

