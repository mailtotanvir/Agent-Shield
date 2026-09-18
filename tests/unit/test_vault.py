import time

import pytest
from fakeredis.aioredis import FakeRedis

from agentshield.errors import ReplayDetectedError, VaultError
from agentshield.secrets.envelope import EnvelopeCipher
from agentshield.secrets.kms.fake import FakeKMSProvider
from agentshield.session.vault import (
    EncryptedTokenVault,
    InMemoryVaultBackend,
    RedisVaultBackend,
    VaultMetadata,
)


def metadata() -> VaultMetadata:
    return VaultMetadata(
        issuer="https://issuer.example",
        subject_fingerprint="abc123",
        client_id="agent",
        audience="api",
        scopes=frozenset({"read"}),
        expires_at_epoch=int(time.time()) + 3600,
    )


@pytest.mark.asyncio
async def test_vault_rotates_without_returning_refresh_token_in_repr() -> None:
    vault = EncryptedTokenVault(
        InMemoryVaultBackend(), EnvelopeCipher(FakeKMSProvider(b"v" * 32))
    )
    session_id = await vault.create("CANARY_REFRESH_ONE", metadata())
    assert "CANARY" not in session_id
    lease = await vault.acquire(session_id)
    assert "CANARY_REFRESH_ONE" not in repr(lease)
    assert lease.refresh_token.get_secret_value() == "CANARY_REFRESH_ONE"
    await vault.commit(lease, "CANARY_REFRESH_TWO")
    next_lease = await vault.acquire(session_id)
    assert next_lease.version == 2
    assert next_lease.refresh_token.get_secret_value() == "CANARY_REFRESH_TWO"


@pytest.mark.asyncio
async def test_vault_allows_only_one_concurrent_refresh_lease() -> None:
    vault = EncryptedTokenVault(
        InMemoryVaultBackend(), EnvelopeCipher(FakeKMSProvider(b"v" * 32))
    )
    session_id = await vault.create("refresh", metadata())
    lease = await vault.acquire(session_id)
    with pytest.raises(VaultError, match="already in progress"):
        await vault.acquire(session_id)
    await vault.abort(lease)
    await vault.acquire(session_id)


@pytest.mark.asyncio
async def test_reused_lease_compromises_family() -> None:
    backend = InMemoryVaultBackend()
    vault = EncryptedTokenVault(backend, EnvelopeCipher(FakeKMSProvider(b"v" * 32)))
    session_id = await vault.create("refresh-1", metadata())
    lease = await vault.acquire(session_id)
    await vault.commit(lease, "refresh-2")
    with pytest.raises(ReplayDetectedError):
        await vault.commit(lease, "refresh-3")
    with pytest.raises(ReplayDetectedError, match="compromised"):
        await vault.acquire(session_id)


@pytest.mark.asyncio
async def test_redis_vault_round_trip_and_delete() -> None:
    redis = FakeRedis(decode_responses=True)
    vault = EncryptedTokenVault(
        RedisVaultBackend(redis, prefix="test:vault"),
        EnvelopeCipher(FakeKMSProvider(b"r" * 32)),
    )
    session_id = await vault.create("refresh-1", metadata())
    lease = await vault.acquire(session_id)
    await vault.commit(lease, "refresh-2")
    rotated = await vault.acquire(session_id)
    assert rotated.refresh_token.get_secret_value() == "refresh-2"
    await vault.abort(rotated)
    await vault.delete(session_id)
    with pytest.raises(VaultError, match="unavailable"):
        await vault.acquire(session_id)
