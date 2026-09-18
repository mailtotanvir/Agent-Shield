import base64
from types import SimpleNamespace

import pytest

from agentshield.errors import SecretAccessDeniedError
from agentshield.secrets.envelope import EnvelopeCipher, EnvelopeContext
from agentshield.secrets.kms.fake import FakeKMSProvider
from agentshield.secrets.kubernetes import (
    TOKEN_AUDIENCE,
    KubernetesSecretReader,
    KubernetesTokenReviewer,
    envelope_secret_name,
)
from agentshield.secrets.models import WorkloadIdentity


class AuthAPI:
    def __init__(self, status: object) -> None:
        self.status = status

    async def create_token_review(self, body: object) -> object:
        assert body.spec.audiences == [TOKEN_AUDIENCE]
        return SimpleNamespace(status=self.status)


@pytest.mark.asyncio
async def test_token_reviewer_requires_pod_bound_service_account() -> None:
    status = SimpleNamespace(
        authenticated=True,
        audiences=[TOKEN_AUDIENCE],
        user=SimpleNamespace(
            username="system:serviceaccount:agents:runner",
            extra={
                "authentication.kubernetes.io/pod-name": ["agent-1"],
                "authentication.kubernetes.io/pod-uid": ["uid-1"],
            },
        ),
    )
    identity = await KubernetesTokenReviewer(AuthAPI(status)).review("token")  # type: ignore[arg-type]
    assert identity.service_account == "runner"
    assert identity.pod_uid == "uid-1"


@pytest.mark.asyncio
async def test_token_reviewer_rejects_wrong_audience() -> None:
    status = SimpleNamespace(authenticated=True, audiences=["other"], user=None)
    with pytest.raises(SecretAccessDeniedError, match="not authenticated"):
        await KubernetesTokenReviewer(AuthAPI(status)).review("token")  # type: ignore[arg-type]


class CoreAPI:
    def __init__(self, encoded_envelope: str) -> None:
        self.encoded_envelope = encoded_envelope

    async def read_namespaced_pod(self, name: str, namespace: str) -> object:
        assert (name, namespace) == ("agent-1", "agents")
        return SimpleNamespace(
            metadata=SimpleNamespace(uid="uid-1", labels={"app": "agent"}),
            spec=SimpleNamespace(service_account_name="runner"),
        )

    async def read_namespaced_secret(self, name: str, namespace: str) -> object:
        assert name == envelope_secret_name("llm-key")
        assert namespace == "agents"
        return SimpleNamespace(data={"envelope.json": self.encoded_envelope})


class CustomAPI:
    async def get_namespaced_custom_object(
        self, group: str, version: str, namespace: str, plural: str, name: str
    ) -> dict[str, object]:
        assert (group, version, namespace, plural, name) == (
            "agentshield.io",
            "v1alpha1",
            "agents",
            "agentsecrets",
            "llm-key",
        )
        return {
            "spec": {
                "access": {
                    "allowedServiceAccounts": [{"name": "runner"}],
                    "scopedTo": {"matchLabels": {"app": "agent"}},
                }
            }
        }


@pytest.mark.asyncio
async def test_secret_reader_verifies_pod_and_envelope_identity() -> None:
    cipher = EnvelopeCipher(FakeKMSProvider(b"k" * 32))
    envelope = await cipher.encrypt(
        b"value", EnvelopeContext(namespace="agents", name="llm-key", generation=1)
    )
    encoded = base64.b64encode(envelope.model_dump_json().encode()).decode()
    reader = KubernetesSecretReader(CoreAPI(encoded), CustomAPI())  # type: ignore[arg-type]
    identity = WorkloadIdentity(
        namespace="agents",
        service_account="runner",
        pod_name="agent-1",
        pod_uid="uid-1",
    )
    observed, policy = await reader.read("agents", "llm-key", identity)
    assert observed == envelope
    assert policy.match_labels == {"app": "agent"}


@pytest.mark.asyncio
async def test_secret_reader_rejects_cross_namespace_before_api_call() -> None:
    reader = KubernetesSecretReader(object(), object())  # type: ignore[arg-type]
    identity = WorkloadIdentity(
        namespace="other",
        service_account="runner",
        pod_name="agent-1",
        pod_uid="uid-1",
    )
    with pytest.raises(SecretAccessDeniedError, match="cross-namespace"):
        await reader.read("agents", "llm-key", identity)
