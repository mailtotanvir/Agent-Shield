"""Configuration with explicit production-mode invariants."""

from enum import StrEnum
from typing import Literal

from pydantic import Field, HttpUrl, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from agentshield.errors import ConfigurationError


class TokenVaultBackend(StrEnum):
    MEMORY = "memory"
    REDIS = "redis"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENTSHIELD_", extra="forbid")

    environment: Literal["development", "test", "production"] = "development"
    issuer: HttpUrl | None = None
    client_id: str | None = None
    allowed_algorithms: tuple[Literal["ES256", "RS256"], ...] = ("ES256", "RS256")
    jwks_cache_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    http_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    clock_skew_seconds: int = Field(default=30, ge=0, le=120)
    kms_provider: Literal["fake", "gcp"] = "fake"
    token_vault: TokenVaultBackend = TokenVaultBackend.MEMORY
    tls_mode: Literal["disabled", "self-signed", "provided"] = "disabled"

    @model_validator(mode="after")
    def enforce_production(self) -> "Settings":
        if self.environment == "production":
            unsafe = []
            if self.kms_provider == "fake":
                unsafe.append("fake KMS")
            if self.token_vault is TokenVaultBackend.MEMORY:
                unsafe.append("in-memory token vault")
            if self.tls_mode != "provided":
                unsafe.append("non-provided TLS")
            if not self.issuer or not self.client_id:
                unsafe.append("missing issuer/client_id")
            if unsafe:
                raise ConfigurationError("unsafe production configuration: " + ", ".join(unsafe))
        return self
