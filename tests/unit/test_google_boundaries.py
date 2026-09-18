import pytest

from agentshield.identity.google import google_accounts_provider
from agentshield.identity.iap import IAP_ISSUER, GoogleIAPTokenValidator


class Validator:
    async def validate(self, assertion: str, policy: object) -> str:
        return assertion


def test_google_oidc_and_iap_have_separate_issuers() -> None:
    provider = google_accounts_provider()
    assert str(provider.issuer).rstrip("/") == "https://accounts.google.com"
    assert IAP_ISSUER != str(provider.issuer).rstrip("/")


def test_iap_requires_resource_audience() -> None:
    with pytest.raises(ValueError, match="full project"):
        GoogleIAPTokenValidator(Validator(), audience="client-id")  # type: ignore[arg-type]
