import logging
import stat
from pathlib import Path

import httpx
import pytest

from agentshield.audit.emitter import AuditEmitter
from agentshield.errors import SecretAccessDeniedError
from agentshield.secrets.broker import SecretBroker, create_app
from agentshield.secrets.envelope import EnvelopeCipher, EnvelopeContext
from agentshield.secrets.kms.fake import FakeKMSProvider
from agentshield.secrets.kubernetes import envelope_secret_name
from agentshield.secrets.models import (
    AllowedServiceAccount,
    SecretAccessPolicy,
    WorkloadIdentity,
)
from agentshield.secrets.operator import validate_spec
from agentshield.secrets.sidecar import atomic_write


class Reviewer:
    async def review(self, token: str) -> WorkloadIdentity:
        assert token == "bound-token"
        return WorkloadIdentity(
            namespace="agents",
            service_account="agent-runner",
            pod_name="agent-1",
            pod_uid="uid-1",
        )


class Reader:
    def __init__(self, envelope: object, policy: SecretAccessPolicy) -> None:
        self.envelope = envelope
        self.policy = policy

    async def read(
        self, namespace: str, name: str, identity: WorkloadIdentity
    ) -> tuple[object, SecretAccessPolicy]:
        assert (namespace, name) == ("agents", "llm-key")
        self.policy.authorize(identity, {"app": "agent"})
        return self.envelope, self.policy


def policy() -> SecretAccessPolicy:
    return SecretAccessPolicy(
        allowed_service_accounts=(
            AllowedServiceAccount(name="agent-runner", namespace="agents"),
        ),
        match_labels={"app": "agent"},
    )


def test_policy_denies_cross_service_account_and_wrong_label() -> None:
    denied_identity = WorkloadIdentity(
        namespace="agents",
        service_account="other",
        pod_name="pod",
        pod_uid="uid",
    )
    with pytest.raises(SecretAccessDeniedError, match="service account"):
        policy().authorize(denied_identity, {"app": "agent"})
    allowed_identity = denied_identity.model_copy(update={"service_account": "agent-runner"})
    with pytest.raises(SecretAccessDeniedError, match="labels"):
        policy().authorize(allowed_identity, {"app": "other"})


@pytest.mark.asyncio
async def test_broker_delivers_without_logging_plaintext(caplog: pytest.LogCaptureFixture) -> None:
    cipher = EnvelopeCipher(FakeKMSProvider(b"b" * 32))
    envelope = await cipher.encrypt(
        b"CANARY_BROKER_SECRET",
        EnvelopeContext(namespace="agents", name="llm-key", generation=3),
    )
    broker = SecretBroker(
        Reviewer(),
        Reader(envelope, policy()),  # type: ignore[arg-type]
        cipher,
        audit=AuditEmitter(logging.getLogger("test.audit")),
    )
    with caplog.at_level(logging.INFO):
        value, generation = await broker.deliver("agents", "llm-key", "Bearer bound-token")
    assert value == b"CANARY_BROKER_SECRET"
    assert generation == 3
    assert "CANARY_BROKER_SECRET" not in caplog.text
    assert "bound-token" not in caplog.text


@pytest.mark.asyncio
async def test_broker_http_response_disables_caching() -> None:
    cipher = EnvelopeCipher(FakeKMSProvider(b"b" * 32))
    envelope = await cipher.encrypt(
        b"value", EnvelopeContext(namespace="agents", name="llm-key", generation=1)
    )
    broker = SecretBroker(Reviewer(), Reader(envelope, policy()), cipher)  # type: ignore[arg-type]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(broker)), base_url="https://broker.test"
    ) as client:
        response = await client.get(
            "/v1/secrets/agents/llm-key", headers={"Authorization": "Bearer bound-token"}
        )
    assert response.status_code == 200
    assert response.content == b"value"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_broker_http_rejects_missing_token() -> None:
    cipher = EnvelopeCipher(FakeKMSProvider(b"b" * 32))
    broker = SecretBroker(Reviewer(), Reader(object(), policy()), cipher)  # type: ignore[arg-type]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(broker)), base_url="https://broker.test"
    ) as client:
        response = await client.get("/v1/secrets/agents/llm-key")
    assert response.status_code == 403


def test_atomic_write_replaces_file_with_owner_only_mode(tmp_path: Path) -> None:
    target = tmp_path / "secret"
    atomic_write(target, b"first")
    atomic_write(target, b"second")
    assert target.read_bytes() == b"second"
    assert stat.S_IMODE(target.stat().st_mode) == 0o400
    assert not list(tmp_path.glob("*.tmp"))


def test_envelope_name_is_bounded_and_stable() -> None:
    name = "a" * 253
    assert envelope_secret_name(name) == envelope_secret_name(name)
    assert len(envelope_secret_name(name)) <= 253


def test_operator_rejects_missing_access_policy() -> None:
    with pytest.raises(Exception, match="ServiceAccount"):
        validate_spec(
            {
                "encryption": {
                    "provider": "gcp-kms",
                    "keyRef": "projects/p/locations/l/keyRings/r/cryptoKeys/k",
                },
                "access": {"allowedServiceAccounts": []},
            }
        )
