from datetime import UTC, datetime

import pytest

from agentshield.errors import ReplayDetectedError, TokenValidationError
from agentshield.session.dpop import DPoPKey, DPoPValidator
from agentshield.session.revocation import InMemoryExpiringStore


@pytest.mark.asyncio
async def test_dpop_request_binding_and_replay_rejection() -> None:
    key = DPoPKey()
    validator = DPoPValidator(InMemoryExpiringStore())
    proof = key.proof("POST", "https://api.example:443/resource?ignored=yes", access_token="access")
    await validator.validate(
        proof,
        method="POST",
        uri="https://api.example/resource?different=yes",
        expected_jkt=key.thumbprint,
        access_token="access",
    )
    with pytest.raises(ReplayDetectedError):
        await validator.validate(
            proof,
            method="POST",
            uri="https://api.example/resource",
            expected_jkt=key.thumbprint,
            access_token="access",
        )


@pytest.mark.asyncio
async def test_dpop_rejects_wrong_method() -> None:
    key = DPoPKey()
    proof = key.proof("GET", "https://api.example/resource", now=datetime.now(UTC))
    with pytest.raises(TokenValidationError, match="binding"):
        await DPoPValidator(InMemoryExpiringStore()).validate(
            proof,
            method="DELETE",
            uri="https://api.example/resource",
            expected_jkt=key.thumbprint,
        )

