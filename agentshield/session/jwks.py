"""Bounded JWKS resolution with refresh coalescing."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import jwt

from agentshield.errors import KeyResolutionError

JWKSFetcher = Callable[[], Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class CachedJWKS:
    keys: dict[str, dict[str, Any]]
    expires_at: float


class JWKSCache:
    def __init__(self, fetcher: JWKSFetcher, *, ttl_seconds: int = 300, max_keys: int = 20) -> None:
        self._fetcher = fetcher
        self._ttl = ttl_seconds
        self._max_keys = max_keys
        self._cached: CachedJWKS | None = None
        self._lock = asyncio.Lock()

    async def resolve(self, kid: str, algorithm: str) -> Any:
        cached = self._cached
        missing = cached is not None and kid not in cached.keys
        if cached is None or cached.expires_at <= time.monotonic() or missing:
            await self._refresh(force=missing)
            cached = self._cached
        if cached is None or kid not in cached.keys:
            raise KeyResolutionError("signing key was not found")
        jwk = cached.keys[kid]
        if jwk.get("use", "sig") != "sig":
            raise KeyResolutionError("JWK is not a signing key")
        if jwk.get("alg") not in {None, algorithm}:
            raise KeyResolutionError("JWK algorithm does not match token")
        try:
            return jwt.PyJWK.from_dict(jwk, algorithm=algorithm).key
        except (jwt.PyJWTError, ValueError, TypeError) as exc:
            raise KeyResolutionError("JWK could not be parsed") from exc

    async def invalidate(self) -> None:
        self._cached = None

    async def _refresh(self, *, force: bool = False) -> None:
        async with self._lock:
            current = self._cached
            if not force and current is not None and current.expires_at > time.monotonic():
                return
            document = await self._fetcher()
            raw_keys = document.get("keys")
            if not isinstance(raw_keys, list) or not raw_keys or len(raw_keys) > self._max_keys:
                raise KeyResolutionError("JWKS has an invalid key count")
            indexed: dict[str, dict[str, Any]] = {}
            for key in raw_keys:
                if not isinstance(key, dict) or not isinstance(key.get("kid"), str):
                    raise KeyResolutionError("JWKS key is missing kid")
                if key["kid"] in indexed:
                    raise KeyResolutionError("JWKS contains duplicate kid")
                indexed[key["kid"]] = key
            self._cached = CachedJWKS(indexed, time.monotonic() + self._ttl)
