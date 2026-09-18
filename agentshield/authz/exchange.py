"""RFC 8693 client; token issuance remains external."""

from __future__ import annotations

import httpx

from agentshield.authz.policy import DelegationPolicy
from agentshield.errors import OAuthProtocolError
from agentshield.models import TokenClaims, TokenExchangeRequest, TokenSet
from agentshield.session.validator import JWTValidator, ValidationPolicy


class TokenExchangeClient:
    def __init__(
        self,
        endpoint: str,
        *,
        client_id: str,
        validator: JWTValidator,
        issuer: str,
        client_secret: str | None = None,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        if not endpoint.startswith("https://"):
            raise ValueError("token exchange endpoint must use HTTPS")
        self._endpoint = endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._validator = validator
        self._issuer = issuer
        self._owns_http = http is None
        self._http = http or httpx.AsyncClient(timeout=5.0, follow_redirects=False)

    async def __aenter__(self) -> TokenExchangeClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def exchange(
        self,
        request: TokenExchangeRequest,
        *,
        subject_claims: TokenClaims,
        policy: DelegationPolicy,
    ) -> TokenSet:
        policy.authorize_request(subject_claims, request)
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": self._client_id,
            "subject_token": request.subject_token,
            "subject_token_type": request.subject_token_type,
            "requested_token_type": request.requested_token_type,
            "scope": " ".join(sorted(request.scopes)),
        }
        if request.audience:
            data["audience"] = request.audience
        if request.resource:
            data["resource"] = request.resource
        if self._client_secret:
            data["client_secret"] = self._client_secret
        try:
            response = await self._http.post(self._endpoint, data=data)
            response.raise_for_status()
            payload = response.json()
            result = TokenSet(
                access_token=payload["access_token"],
                token_type=payload.get("token_type", "Bearer"),
                expires_in=int(payload["expires_in"]),
                refresh_token=payload.get("refresh_token"),
                scope=tuple(payload.get("scope", "").split()),
            )
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            raise OAuthProtocolError("token exchange failed") from exc
        audience = request.audience or request.resource
        if audience is None:  # guarded by policy, retained for type narrowing
            raise OAuthProtocolError("token exchange has no target")
        result_claims = await self._validator.validate(
            result.access_token,
            ValidationPolicy(issuer=self._issuer, audience=audience),
        )
        policy.validate_result(subject_claims, result_claims, request)
        return result

