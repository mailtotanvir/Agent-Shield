"""Identity connector protocol."""

from typing import Protocol

from agentshield.models import AuthorizationRequest, CodeExchangeRequest, TokenSet


class IdentityConnector(Protocol):
    async def authorization_url(self, request: AuthorizationRequest) -> str: ...

    async def exchange_code(self, request: CodeExchangeRequest) -> TokenSet: ...

    async def refresh(self, refresh_token: str) -> TokenSet: ...

    async def revoke(self, token: str, token_type_hint: str) -> None: ...

