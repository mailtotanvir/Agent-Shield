import pytest

from agentshield.errors import EnvelopeError
from agentshield.secrets.envelope import EncryptedEnvelope, EnvelopeCipher, EnvelopeContext
from agentshield.secrets.kms.fake import FakeKMSProvider


@pytest.mark.asyncio
async def test_envelope_round_trip_and_no_plaintext_serialization() -> None:
    cipher = EnvelopeCipher(FakeKMSProvider(b"k" * 32))
    context = EnvelopeContext(namespace="agents", name="llm-key", generation=1)
    envelope = await cipher.encrypt(b"CANARY_SECRET", context)
    assert "CANARY_SECRET" not in envelope.model_dump_json()
    assert await cipher.decrypt(envelope) == b"CANARY_SECRET"


@pytest.mark.asyncio
async def test_context_tampering_fails_closed() -> None:
    cipher = EnvelopeCipher(FakeKMSProvider(b"k" * 32))
    envelope = await cipher.encrypt(
        b"CANARY_SECRET", EnvelopeContext(namespace="agents", name="llm-key", generation=1)
    )
    tampered = EncryptedEnvelope.model_validate(
        {
            **envelope.model_dump(),
            "context": {"namespace": "other", "name": "llm-key", "generation": 1},
        }
    )
    with pytest.raises(EnvelopeError):
        await cipher.decrypt(tampered)

