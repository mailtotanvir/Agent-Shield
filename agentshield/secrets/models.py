"""Kubernetes secret-access policy models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from agentshield.errors import SecretAccessDeniedError


class WorkloadIdentity(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    namespace: str
    service_account: str
    pod_name: str
    pod_uid: str


class AllowedServiceAccount(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=253)
    namespace: str = Field(min_length=1, max_length=253)


class SecretAccessPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_service_accounts: tuple[AllowedServiceAccount, ...]
    match_labels: dict[str, str] = Field(default_factory=dict)

    def authorize(self, identity: WorkloadIdentity, pod_labels: dict[str, str]) -> None:
        allowed = any(
            candidate.name == identity.service_account
            and candidate.namespace == identity.namespace
            for candidate in self.allowed_service_accounts
        )
        if not allowed:
            raise SecretAccessDeniedError("service account is not allowed")
        if any(pod_labels.get(key) != value for key, value in self.match_labels.items()):
            raise SecretAccessDeniedError("pod labels do not satisfy secret policy")

