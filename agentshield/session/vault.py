"""KMS-envelope-encrypted refresh-token custody."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from agentshield.audit.redactor import fingerprint
from agentshield.errors import ReplayDetectedError, VaultError
from agentshield.secrets.envelope import EncryptedEnvelope, EnvelopeCipher, EnvelopeContext


class VaultMetadata(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    issuer: str
    subject_fingerprint: str
    client_id: str
    audience: str
    scopes: frozenset[str]
    expires_at_epoch: int


class VaultRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = Field(ge=1)
    family_id: str
    status: Literal["active", "refreshing", "compromised"] = "active"
    lease_id: str | None = None
    lease_expires_at: float | None = None
    refresh_fingerprint: str
    metadata: VaultMetadata
    envelope: EncryptedEnvelope


class RefreshLease(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    session_digest: str
    family_id: str
    version: int
    lease_id: str
    refresh_token: SecretStr
    metadata: VaultMetadata


class VaultBackend(Protocol):
    async def create(self, digest: str, record: VaultRecord, ttl_seconds: int) -> None: ...

    async def acquire(self, digest: str, lease_id: str, lease_seconds: int) -> VaultRecord: ...

    async def commit(
        self, digest: str, lease_id: str, replacement: VaultRecord, ttl_seconds: int
    ) -> None: ...

    async def abort(self, digest: str, lease_id: str) -> None: ...

    async def compromise_family(self, family_id: str) -> None: ...

    async def delete(self, digest: str) -> None: ...


class InMemoryVaultBackend:
    """Test-only backend with the same lease state machine as Redis."""

    def __init__(self) -> None:
        self._records: dict[str, tuple[VaultRecord, float]] = {}
        self._family_members: dict[str, set[str]] = {}
        self._compromised: set[str] = set()
        self._lock = asyncio.Lock()

    async def create(self, digest: str, record: VaultRecord, ttl_seconds: int) -> None:
        async with self._lock:
            if digest in self._records:
                raise VaultError("session already exists")
            self._records[digest] = (record, time.time() + ttl_seconds)
            self._family_members.setdefault(record.family_id, set()).add(digest)

    async def acquire(self, digest: str, lease_id: str, lease_seconds: int) -> VaultRecord:
        async with self._lock:
            item = self._records.get(digest)
            if item is None or item[1] <= time.time():
                self._records.pop(digest, None)
                raise VaultError("session is unavailable")
            record, expiry = item
            if record.family_id in self._compromised or record.status == "compromised":
                raise ReplayDetectedError("token family is compromised")
            if record.status == "refreshing" and (record.lease_expires_at or 0) > time.time():
                raise VaultError("refresh is already in progress")
            acquired = record.model_copy(
                update={
                    "status": "refreshing",
                    "lease_id": lease_id,
                    "lease_expires_at": time.time() + lease_seconds,
                }
            )
            self._records[digest] = (acquired, expiry)
            return acquired.model_copy(deep=True)

    async def commit(
        self, digest: str, lease_id: str, replacement: VaultRecord, ttl_seconds: int
    ) -> None:
        async with self._lock:
            item = self._records.get(digest)
            if item is None or item[0].lease_id != lease_id or item[0].status != "refreshing":
                self._compromised.add(replacement.family_id)
                raise ReplayDetectedError("refresh lease was reused")
            if replacement.family_id in self._compromised:
                raise ReplayDetectedError("token family is compromised")
            self._records[digest] = (replacement, time.time() + ttl_seconds)

    async def abort(self, digest: str, lease_id: str) -> None:
        async with self._lock:
            item = self._records.get(digest)
            if item and item[0].lease_id == lease_id:
                self._records[digest] = (
                    item[0].model_copy(
                        update={"status": "active", "lease_id": None, "lease_expires_at": None}
                    ),
                    item[1],
                )

    async def compromise_family(self, family_id: str) -> None:
        async with self._lock:
            self._compromised.add(family_id)
            for digest in self._family_members.get(family_id, set()):
                item = self._records.get(digest)
                if item:
                    self._records[digest] = (
                        item[0].model_copy(update={"status": "compromised"}),
                        item[1],
                    )

    async def delete(self, digest: str) -> None:
        async with self._lock:
            item = self._records.pop(digest, None)
            if item:
                self._family_members.get(item[0].family_id, set()).discard(digest)


class RedisVaultBackend:
    """Redis backend using optimistic transactions and a family kill switch."""

    def __init__(self, redis_client: Any, *, prefix: str = "agentshield:vault") -> None:
        self._redis = redis_client
        self._prefix = prefix

    def _session_key(self, digest: str) -> str:
        return f"{self._prefix}:session:{digest}"

    def _family_key(self, family_id: str) -> str:
        return f"{self._prefix}:family:{family_id}"

    def _compromised_key(self, family_id: str) -> str:
        return f"{self._prefix}:compromised:{family_id}"

    async def create(self, digest: str, record: VaultRecord, ttl_seconds: int) -> None:
        created = await self._redis.set(
            self._session_key(digest), record.model_dump_json(), ex=ttl_seconds, nx=True
        )
        if not created:
            raise VaultError("session already exists")
        await self._redis.sadd(self._family_key(record.family_id), digest)
        await self._redis.expire(self._family_key(record.family_id), ttl_seconds)

    async def acquire(self, digest: str, lease_id: str, lease_seconds: int) -> VaultRecord:
        key = self._session_key(digest)
        for _attempt in range(3):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    if raw is None:
                        raise VaultError("session is unavailable")
                    record = VaultRecord.model_validate_json(raw)
                    if await self._redis.exists(self._compromised_key(record.family_id)):
                        raise ReplayDetectedError("token family is compromised")
                    if (
                        record.status == "refreshing"
                        and (record.lease_expires_at or 0) > time.time()
                    ):
                        raise VaultError("refresh is already in progress")
                    acquired = record.model_copy(
                        update={
                            "status": "refreshing",
                            "lease_id": lease_id,
                            "lease_expires_at": time.time() + lease_seconds,
                        }
                    )
                    pipe.multi()
                    pipe.set(key, acquired.model_dump_json(), keepttl=True)
                    await pipe.execute()
                    return acquired
                except VaultError:
                    raise
                except Exception as exc:
                    if exc.__class__.__name__ != "WatchError":
                        raise VaultError("Redis vault acquire failed") from exc
        raise VaultError("Redis vault contention limit exceeded")

    async def commit(
        self, digest: str, lease_id: str, replacement: VaultRecord, ttl_seconds: int
    ) -> None:
        key = self._session_key(digest)
        async with self._redis.pipeline(transaction=True) as pipe:
            try:
                await pipe.watch(key)
                raw = await pipe.get(key)
                current = VaultRecord.model_validate_json(raw) if raw else None
                if (
                    current is None
                    or current.status != "refreshing"
                    or current.lease_id != lease_id
                ):
                    await self.compromise_family(replacement.family_id)
                    raise ReplayDetectedError("refresh lease was reused")
                if await self._redis.exists(self._compromised_key(replacement.family_id)):
                    raise ReplayDetectedError("token family is compromised")
                pipe.multi()
                pipe.set(key, replacement.model_dump_json(), ex=ttl_seconds)
                await pipe.execute()
            except (VaultError, ReplayDetectedError):
                raise
            except Exception as exc:
                raise VaultError("Redis vault commit failed") from exc

    async def abort(self, digest: str, lease_id: str) -> None:
        key = self._session_key(digest)
        raw = await self._redis.get(key)
        if raw is None:
            return
        record = VaultRecord.model_validate_json(raw)
        if record.lease_id == lease_id:
            active = record.model_copy(
                update={"status": "active", "lease_id": None, "lease_expires_at": None}
            )
            await self._redis.set(key, active.model_dump_json(), keepttl=True)

    async def compromise_family(self, family_id: str) -> None:
        await self._redis.set(self._compromised_key(family_id), "1", ex=86_400)

    async def delete(self, digest: str) -> None:
        await self._redis.delete(self._session_key(digest))


class EncryptedTokenVault:
    def __init__(
        self,
        backend: VaultBackend,
        cipher: EnvelopeCipher,
        *,
        lease_seconds: int = 30,
        maximum_ttl_seconds: int = 86_400,
    ) -> None:
        self._backend = backend
        self._cipher = cipher
        self._lease_seconds = lease_seconds
        self._maximum_ttl = maximum_ttl_seconds

    @staticmethod
    def _digest(session_id: str) -> str:
        return hashlib.sha256(session_id.encode()).hexdigest()

    async def create(self, refresh_token: str, metadata: VaultMetadata) -> str:
        now = int(time.time())
        ttl = min(metadata.expires_at_epoch - now, self._maximum_ttl)
        if ttl <= 0:
            raise VaultError("refresh token is already expired")
        session_id = secrets.token_urlsafe(32)
        digest = self._digest(session_id)
        family_id = secrets.token_urlsafe(24)
        envelope = await self._cipher.encrypt(
            refresh_token.encode(),
            EnvelopeContext(namespace="sessions", name=digest, generation=1),
        )
        record = VaultRecord(
            version=1,
            family_id=family_id,
            refresh_fingerprint=fingerprint(refresh_token),
            metadata=metadata,
            envelope=envelope,
        )
        await self._backend.create(digest, record, ttl)
        return session_id

    async def acquire(self, session_id: str) -> RefreshLease:
        digest = self._digest(session_id)
        lease_id = secrets.token_urlsafe(24)
        record = await self._backend.acquire(digest, lease_id, self._lease_seconds)
        plaintext = await self._cipher.decrypt(record.envelope)
        try:
            token = plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            await self._backend.abort(digest, lease_id)
            raise VaultError("stored refresh token is malformed") from exc
        return RefreshLease(
            session_digest=digest,
            family_id=record.family_id,
            version=record.version,
            lease_id=lease_id,
            refresh_token=SecretStr(token),
            metadata=record.metadata,
        )

    async def commit(self, lease: RefreshLease, refresh_token: str) -> None:
        version = lease.version + 1
        envelope = await self._cipher.encrypt(
            refresh_token.encode(),
            EnvelopeContext(namespace="sessions", name=lease.session_digest, generation=version),
        )
        ttl = min(lease.metadata.expires_at_epoch - int(time.time()), self._maximum_ttl)
        if ttl <= 0:
            await self._backend.compromise_family(lease.family_id)
            raise VaultError("session expired during refresh")
        replacement = VaultRecord(
            version=version,
            family_id=lease.family_id,
            refresh_fingerprint=fingerprint(refresh_token),
            metadata=lease.metadata,
            envelope=envelope,
        )
        await self._backend.commit(lease.session_digest, lease.lease_id, replacement, ttl)

    async def abort(self, lease: RefreshLease) -> None:
        await self._backend.abort(lease.session_digest, lease.lease_id)

    async def compromise(self, lease: RefreshLease) -> None:
        await self._backend.compromise_family(lease.family_id)

    async def delete(self, session_id: str) -> None:
        await self._backend.delete(self._digest(session_id))
