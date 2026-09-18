from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx

from agentshield.errors import OAuthProtocolError
from agentshield.identity.oidc import (
    OIDCConnector,
    OIDCProvider,
    create_pkce_verifier,
    load_provider,
    pkce_challenge,
)
from agentshield.models import AuthorizationRequest, CodeExchangeRequest


@pytest.mark.asyncio
async def test_authorization_url_always_uses_s256() -> None:
    provider = OIDCProvider(
        issuer="https://issuer.example",
        authorization_endpoint="https://issuer.example/authorize",
        token_endpoint="https://issuer.example/token",
        jwks_uri="https://issuer.example/jwks",
    )
    verifier = create_pkce_verifier()
    request = AuthorizationRequest(
        scopes=("openid", "profile"),
        redirect_uri="https://client.example/callback",
        state="state-value-long-enough",
        nonce="nonce-value-long-enough",
        pkce_verifier=verifier,
    )
    async with OIDCConnector(provider, client_id="client") as connector:
        url = await connector.authorization_url(request)
    query = parse_qs(urlsplit(url).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == [pkce_challenge(verifier)]
    assert "code_verifier" not in query


@pytest.mark.asyncio
@respx.mock
async def test_discovery_rejects_non_allowlisted_endpoint() -> None:
    respx.get("https://issuer.example/.well-known/openid-configuration").mock(
        return_value=httpx.Response(
            200,
            json={
                "issuer": "https://issuer.example",
                "authorization_endpoint": "https://issuer.example/authorize",
                "token_endpoint": "https://attacker.example/token",
                "jwks_uri": "https://issuer.example/jwks",
            },
        )
    )
    with pytest.raises(OAuthProtocolError, match="not allowlisted"):
        await load_provider(
            "https://issuer.example",
            allowed_endpoint_hosts=frozenset({"issuer.example"}),
        )


@pytest.mark.asyncio
@respx.mock
async def test_code_exchange_and_revocation_do_not_leak_protocol_details() -> None:
    provider = OIDCProvider(
        issuer="https://issuer.example",
        authorization_endpoint="https://issuer.example/authorize",
        token_endpoint="https://issuer.example/token",
        jwks_uri="https://issuer.example/jwks",
        revocation_endpoint="https://issuer.example/revoke",
    )
    token_route = respx.post("https://issuer.example/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "access",
                "refresh_token": "refresh",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "openid profile",
            },
        )
    )
    revoke_route = respx.post("https://issuer.example/revoke").mock(
        return_value=httpx.Response(200)
    )
    verifier = create_pkce_verifier()
    async with OIDCConnector(
        provider, client_id="client", client_secret="client-secret"
    ) as connector:
        result = await connector.exchange_code(
            CodeExchangeRequest(
                code="code",
                redirect_uri="https://client.example/callback",
                pkce_verifier=verifier,
            )
        )
        await connector.revoke(result.refresh_token or "", "refresh_token")
    assert result.scope == ("openid", "profile")
    assert token_route.called
    assert revoke_route.called
    assert "client_secret" in token_route.calls[0].request.content.decode()


@pytest.mark.asyncio
@respx.mock
async def test_valid_discovery_ignores_unrelated_metadata() -> None:
    respx.get("https://issuer.example/.well-known/openid-configuration").mock(
        return_value=httpx.Response(
            200,
            json={
                "issuer": "https://issuer.example",
                "authorization_endpoint": "https://issuer.example/authorize",
                "token_endpoint": "https://issuer.example/token",
                "jwks_uri": "https://issuer.example/jwks",
                "unrelated_supported_feature": ["safe-to-ignore"],
            },
        )
    )
    provider = await load_provider(
        "https://issuer.example", allowed_endpoint_hosts=frozenset({"issuer.example"})
    )
    assert str(provider.issuer).rstrip("/") == "https://issuer.example"
