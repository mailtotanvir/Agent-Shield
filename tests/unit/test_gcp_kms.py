from types import SimpleNamespace

import pytest

from agentshield.errors import EnvelopeError
from agentshield.secrets.kms.gcp import GCPKMSProvider, _crc32c


class KMSClient:
    async def encrypt(self, request: dict[str, object]) -> object:
        assert request["name"] == "projects/p/locations/l/keyRings/r/cryptoKeys/k"
        value = b"wrapped"
        return SimpleNamespace(
            verified_plaintext_crc32c=True,
            verified_additional_authenticated_data_crc32c=True,
            ciphertext=value,
            ciphertext_crc32c=_crc32c(value),
        )

    async def decrypt(self, request: dict[str, object]) -> object:
        value = b"d" * 32
        return SimpleNamespace(
            verified_ciphertext_crc32c=True,
            verified_additional_authenticated_data_crc32c=True,
            plaintext=value,
            plaintext_crc32c=_crc32c(value),
        )


@pytest.mark.asyncio
async def test_gcp_kms_checks_round_trip_integrity() -> None:
    provider = GCPKMSProvider(
        "projects/p/locations/l/keyRings/r/cryptoKeys/k", client=KMSClient()  # type: ignore[arg-type]
    )
    wrapped = await provider.wrap_key(b"d" * 32, b"aad")
    assert wrapped == b"wrapped"
    assert await provider.unwrap_key(wrapped, b"aad") == b"d" * 32


class BadKMSClient(KMSClient):
    async def encrypt(self, request: dict[str, object]) -> object:
        response = await super().encrypt(request)
        response.verified_plaintext_crc32c = False
        return response


@pytest.mark.asyncio
async def test_gcp_kms_rejects_failed_integrity_flag() -> None:
    provider = GCPKMSProvider(
        "projects/p/locations/l/keyRings/r/cryptoKeys/k", client=BadKMSClient()  # type: ignore[arg-type]
    )
    with pytest.raises(EnvelopeError, match="integrity"):
        await provider.wrap_key(b"d" * 32, b"aad")
