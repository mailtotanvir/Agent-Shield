"""Minimal key-wrapping interface."""

from typing import Protocol


class KMSProvider(Protocol):
    @property
    def key_ref(self) -> str: ...

    async def wrap_key(self, plaintext_dek: bytes, context: bytes) -> bytes: ...

    async def unwrap_key(self, wrapped_dek: bytes, context: bytes) -> bytes: ...

