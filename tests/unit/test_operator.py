from types import SimpleNamespace

import pytest

from agentshield.secrets.operator import mark_rotation_due, reconcile, validate_spec


def valid_spec() -> dict[str, object]:
    return {
        "encryption": {
            "provider": "gcp-kms",
            "keyRef": "projects/p/locations/l/keyRings/r/cryptoKeys/k",
        },
        "access": {"allowedServiceAccounts": [{"name": "runner"}]},
    }


def test_validate_spec_accepts_bounded_initial_provider() -> None:
    validate_spec(valid_spec())


class CoreAPI:
    async def read_namespaced_secret(self, name: str, namespace: str) -> object:
        return SimpleNamespace(
            metadata=SimpleNamespace(annotations={"agentshield.io/generation": "2"}),
            data={"envelope.json": "ciphertext"},
        )


@pytest.mark.asyncio
async def test_reconcile_reports_ready_envelope() -> None:
    status = await reconcile(
        name="llm-key",
        namespace="agents",
        uid="uid",
        generation=4,
        spec=valid_spec(),
        core=CoreAPI(),
    )
    assert status["envelopeGeneration"] == 2
    assert status["conditions"][0]["status"] == "True"


@pytest.mark.asyncio
async def test_rotation_without_previous_value_is_due() -> None:
    patch: dict[str, object] = {}
    await mark_rotation_due(
        spec={"rotation": {"enabled": True, "intervalHours": 24}},
        status={},
        patch=patch,
    )
    assert patch == {"status": {"rotationDue": True}}

