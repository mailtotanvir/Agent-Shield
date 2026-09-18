"""Deterministic-interface local KMS; forbidden in production configuration."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agentshield.errors import EnvelopeError


class FakeKMSProvider:
    def __init__(self, key: bytes | None = None, *, key_ref: str = "fake://local-test-key") -> None:
        self._key = key or AESGCM.generate_key(bit_length=256)
        self._key_ref = key_ref
        if len(self._key) != 32:
            raise ValueError("fake KMS key must be 32 bytes")

    @property
    def key_ref(self) -> str:
        return self._key_ref

    async def wrap_key(self, plaintext_dek: bytes, context: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(self._key).encrypt(nonce, plaintext_dek, context)

    async def unwrap_key(self, wrapped_dek: bytes, context: bytes) -> bytes:
        if len(wrapped_dek) < 29:
            raise EnvelopeError("wrapped DEK is malformed")
        try:
            return AESGCM(self._key).decrypt(wrapped_dek[:12], wrapped_dek[12:], context)
        except Exception as exc:
            raise EnvelopeError("KMS unwrap failed") from exc
