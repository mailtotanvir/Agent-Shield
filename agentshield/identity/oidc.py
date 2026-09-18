"""Strict, configuration-pinned OIDC/OAuth client."""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import urlencode, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, HttpUrl, field_validator

from agentshield.errors import OAuthProtocolError
from agentshield.models import AuthorizationRequest, CodeExchangeRequest, PKCEVerifier, TokenSet


class OIDCProvider(BaseModel):
    """Validated endpoints; normally produced from pinned discovery."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    issuer: HttpUrl
    authorization_endpoint: HttpUrl
    token_endpoint: HttpUrl
    jwks_uri: HttpUrl
    revocation_endpoint: HttpUrl | None = None
    token_exchange_endpoint: HttpUrl | None = None

    @field_validator(
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "revocation_endpoint",
        "token_exchange_endpoint",
    )
    @classmethod
    def require_https(cls, value: HttpUrl | None) -> HttpUrl | None:
        if value is not None and value.scheme != "https":
            raise ValueError("OIDC endpoints must use HTTPS")
        if value is not None and (value.username or value.password or value.fragment):
            raise ValueError("OIDC endpoint contains forbidden URL components")
        return value


def create_pkce_verifier() -> PKCEVerifier:
    return PKCEVerifier(value=secrets.token_urlsafe(64)[:86])


def pkce_challenge(verifier: PKCEVerifier) -> str:
    digest = hashlib.sha256(verifier.value.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class OIDCConnector:
    def __init__(
        self,
        provider: OIDCProvider,
        *,
        client_id: str,
        client_secret: str | None = None,
        timeout: float = 5.0,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self.provider = provider
        self.client_id = client_id
        self._client_secret = client_secret
        self._owns_http = http is None
        self._http = http or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    async def __aenter__(self) -> OIDCConnector:
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def authorization_url(self, request: AuthorizationRequest) -> str:
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": str(request.redirect_uri),
                "scope": " ".join(request.scopes),
                "state": request.state,
                "nonce": request.nonce,
                "code_challenge": pkce_challenge(request.pkce_verifier),
                "code_challenge_method": "S256",
            }
        )
        return f"{self.provider.authorization_endpoint}?{query}"

    async def exchange_code(self, request: CodeExchangeRequest) -> TokenSet:
        return await self._token_request(
            {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": request.code,
                "redirect_uri": str(request.redirect_uri),
                "code_verifier": request.pkce_verifier.value,
            }
        )

    async def client_credentials(self, scopes: tuple[str, ...]) -> TokenSet:
        return await self._token_request(
            {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "scope": " ".join(scopes),
            }
        )

    async def refresh(self, refresh_token: str) -> TokenSet:
        return await self._token_request(
            {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": refresh_token,
            }
        )

    async def revoke(self, token: str, token_type_hint: str) -> None:
        if self.provider.revocation_endpoint is None:
            raise OAuthProtocolError("provider does not advertise revocation")
        data = {
            "client_id": self.client_id,
            "token": token,
            "token_type_hint": token_type_hint,
        }
        if self._client_secret is not None:
            data["client_secret"] = self._client_secret
        try:
            response = await self._http.post(str(self.provider.revocation_endpoint), data=data)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise OAuthProtocolError("token revocation failed") from exc

    async def _token_request(self, data: dict[str, str]) -> TokenSet:
        if self._client_secret is not None:
            data = {**data, "client_secret": self._client_secret}
        try:
            response = await self._http.post(str(self.provider.token_endpoint), data=data)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OAuthProtocolError("token endpoint request failed") from exc
        if not isinstance(payload, dict):
            raise OAuthProtocolError("token endpoint returned an invalid document")
        try:
            scope_value = payload.get("scope", "")
            scopes = tuple(scope_value.split()) if isinstance(scope_value, str) else ()
            return TokenSet(
                access_token=payload["access_token"],
                token_type=payload.get("token_type", "Bearer"),
                expires_in=int(payload["expires_in"]),
                refresh_token=payload.get("refresh_token"),
                id_token=payload.get("id_token"),
                scope=scopes,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise OAuthProtocolError("token endpoint response is missing required fields") from exc


async def load_provider(
    issuer: str,
    *,
    allowed_endpoint_hosts: frozenset[str],
    request_timeout: float = 5.0,
    http: httpx.AsyncClient | None = None,
) -> OIDCProvider:
    """Load discovery without allowing it to redirect requests to arbitrary hosts."""

    normalized_issuer = issuer.rstrip("/")
    parsed = urlsplit(normalized_issuer)
    if parsed.scheme != "https" or not parsed.hostname:
        raise OAuthProtocolError("issuer must be an absolute HTTPS URL")
    client = http or httpx.AsyncClient(timeout=request_timeout, follow_redirects=False)
    owns_client = http is None
    try:
        response = await client.get(f"{normalized_issuer}/.well-known/openid-configuration")
        response.raise_for_status()
        if len(response.content) > 1_000_000:
            raise OAuthProtocolError("discovery document exceeds size limit")
        payload = response.json()
        if (
            not isinstance(payload, dict)
            or payload.get("issuer", "").rstrip("/") != normalized_issuer
        ):
            raise OAuthProtocolError("discovery issuer mismatch")
        provider = OIDCProvider.model_validate(
            {
                name: payload.get(name)
                for name in OIDCProvider.model_fields
                if payload.get(name) is not None
            }
        )
        endpoints = [
            provider.authorization_endpoint,
            provider.token_endpoint,
            provider.jwks_uri,
            provider.revocation_endpoint,
            provider.token_exchange_endpoint,
        ]
        for endpoint in endpoints:
            if endpoint is not None and endpoint.host not in allowed_endpoint_hosts:
                raise OAuthProtocolError("discovery endpoint host is not allowlisted")
        return provider
    except httpx.HTTPError as exc:
        raise OAuthProtocolError("OIDC discovery failed") from exc
    finally:
        if owns_client:
            await client.aclose()
