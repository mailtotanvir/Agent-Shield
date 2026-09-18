import pytest

from agentshield.config import Settings
from agentshield.errors import ConfigurationError


def test_production_rejects_development_adapters() -> None:
    with pytest.raises(ConfigurationError, match="unsafe production configuration"):
        Settings(environment="production")


def test_production_accepts_explicit_secure_adapters() -> None:
    settings = Settings(
        environment="production",
        issuer="https://issuer.example",
        client_id="agent",
        kms_provider="gcp",
        token_vault="redis",
        tls_mode="provided",
    )
    assert settings.environment == "production"

