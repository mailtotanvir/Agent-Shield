"""Revocation and replay stores."""

from __future__ import annotations

import time
from typing import Any, Protocol


class ExpiringStore(Protocol):
    async def add_once(self, key: str, ttl_seconds: int) -> bool: ...

    async def contains(self, key: str) -> bool: ...


class InMemoryExpiringStore:
    def __init__(self) -> None:
        self._values: dict[str, float] = {}

    def _prune(self) -> None:
        now = time.monotonic()
        self._values = {key: expiry for key, expiry in self._values.items() if expiry > now}

    async def add_once(self, key: str, ttl_seconds: int) -> bool:
        self._prune()
        if key in self._values:
            return False
        self._values[key] = time.monotonic() + ttl_seconds
        return True

    async def contains(self, key: str) -> bool:
        self._prune()
        return key in self._values


class RedisExpiringStore:
    def __init__(self, redis_client: Any, *, prefix: str) -> None:
        self._redis = redis_client
        self._prefix = prefix

    async def add_once(self, key: str, ttl_seconds: int) -> bool:
        result = await self._redis.set(f"{self._prefix}:{key}", "1", ex=ttl_seconds, nx=True)
        return bool(result)

    async def contains(self, key: str) -> bool:
        return bool(await self._redis.exists(f"{self._prefix}:{key}"))
