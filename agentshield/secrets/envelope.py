"""Versioned AES-256-GCM envelope encryption."""

from __future__ import annotations

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field

from agentshield.errors import EnvelopeError
from agentshield.secrets.kms.base import KMSProvider


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise EnvelopeError("envelope contains invalid base64") from exc


class EnvelopeContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    namespace: str = Field(min_length=1, max_length=253)
    name: str = Field(min_length=1, max_length=253)
    generation: int = Field(ge=1)
    schema_version: int = 1

    def aad(self) -> bytes:
        return json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":")).encode()


class EncryptedEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int = 1
    algorithm: str = "AES-256-GCM"
    key_ref: str
    context: EnvelopeContext
    nonce: str
    ciphertext: str
    wrapped_dek: str


class EnvelopeCipher:
    def __init__(self, kms_provider: KMSProvider, *, max_plaintext_bytes: int = 1_048_576) -> None:
        self._kms = kms_provider
        self._max_plaintext = max_plaintext_bytes

    async def encrypt(self, plaintext: bytes, context: EnvelopeContext) -> EncryptedEnvelope:
        if not plaintext or len(plaintext) > self._max_plaintext:
            raise EnvelopeError("plaintext size is outside allowed bounds")
        dek = bytearray(AESGCM.generate_key(bit_length=256))
        nonce = os.urandom(12)
        aad = context.aad()
        try:
            ciphertext = AESGCM(bytes(dek)).encrypt(nonce, plaintext, aad)
            wrapped = await self._kms.wrap_key(bytes(dek), aad)
            return EncryptedEnvelope(
                key_ref=self._kms.key_ref,
                context=context,
                nonce=_encode(nonce),
                ciphertext=_encode(ciphertext),
                wrapped_dek=_encode(wrapped),
            )
        finally:
            dek[:] = b"\x00" * len(dek)

    async def decrypt(self, envelope: EncryptedEnvelope) -> bytes:
        if envelope.version != 1 or envelope.algorithm != "AES-256-GCM":
            raise EnvelopeError("unsupported envelope version or algorithm")
        if envelope.key_ref != self._kms.key_ref:
            raise EnvelopeError("envelope key reference mismatch")
        aad = envelope.context.aad()
        dek = bytearray(await self._kms.unwrap_key(_decode(envelope.wrapped_dek), aad))
        if len(dek) != 32:
            dek[:] = b"\x00" * len(dek)
            raise EnvelopeError("unwrapped DEK has invalid length")
        try:
            return AESGCM(bytes(dek)).decrypt(
                _decode(envelope.nonce), _decode(envelope.ciphertext), aad
            )
        except InvalidTag as exc:
            raise EnvelopeError("envelope authentication failed") from exc
        finally:
            dek[:] = b"\x00" * len(dek)

