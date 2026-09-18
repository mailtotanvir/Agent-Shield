"""Google IAP assertion validation, separate from interactive Google OIDC."""

from agentshield.models import TokenClaims
from agentshield.session.validator import JWTValidator, ValidationPolicy

IAP_ISSUER = "https://cloud.google.com/iap"


class GoogleIAPTokenValidator:
    def __init__(self, validator: JWTValidator, *, audience: str) -> None:
        if not audience.startswith("/projects/"):
            raise ValueError("IAP audience must be a full project resource audience")
        self._validator = validator
        self._policy = ValidationPolicy(
            issuer=IAP_ISSUER,
            audience=audience,
            allowed_algorithms=("ES256",),
        )

    async def validate(self, assertion: str) -> TokenClaims:
        return await self._validator.validate(assertion, self._policy)

