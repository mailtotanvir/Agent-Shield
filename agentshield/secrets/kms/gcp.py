"""Google Cloud KMS key wrapping with integrity checks."""

from __future__ import annotations

from typing import Any

import google_crc32c
from google.cloud import kms

from agentshield.errors import EnvelopeError


def _crc32c(value: bytes) -> int:
    checksum = google_crc32c.Checksum()  # type: ignore[no-untyped-call]
    checksum.update(value)  # type: ignore[no-untyped-call]
    return int(checksum.hexdigest(), 16)  # type: ignore[no-untyped-call]


class GCPKMSProvider:
    def __init__(
        self, key_ref: str, client: kms.KeyManagementServiceAsyncClient | None = None
    ) -> None:
        if not key_ref.startswith("projects/") or "/cryptoKeys/" not in key_ref:
            raise ValueError("key_ref must be a full Cloud KMS CryptoKey resource name")
        self._key_ref = key_ref
        self._client = client or kms.KeyManagementServiceAsyncClient()

    @property
    def key_ref(self) -> str:
        return self._key_ref

    async def wrap_key(self, plaintext_dek: bytes, context: bytes) -> bytes:
        plaintext_crc = _crc32c(plaintext_dek)
        aad_crc = _crc32c(context)

        try:
            response: Any = await self._client.encrypt(
                request={
                    "name": self._key_ref,
                    "plaintext": plaintext_dek,
                    "plaintext_crc32c": plaintext_crc,
                    "additional_authenticated_data": context,
                    "additional_authenticated_data_crc32c": aad_crc,
                }
            )
            if (
                not response.verified_plaintext_crc32c
                or not response.verified_additional_authenticated_data_crc32c
            ):
                raise EnvelopeError("Cloud KMS rejected request integrity checks")
            ciphertext = bytes(response.ciphertext)
            if _crc32c(ciphertext) != response.ciphertext_crc32c:
                raise EnvelopeError("Cloud KMS ciphertext integrity check failed")
            return ciphertext
        except EnvelopeError:
            raise
        except Exception as exc:
            raise EnvelopeError("Cloud KMS encrypt failed") from exc

    async def unwrap_key(self, wrapped_dek: bytes, context: bytes) -> bytes:
        ciphertext_crc = _crc32c(wrapped_dek)
        aad_crc = _crc32c(context)

        try:
            response: Any = await self._client.decrypt(
                request={
                    "name": self._key_ref,
                    "ciphertext": wrapped_dek,
                    "ciphertext_crc32c": ciphertext_crc,
                    "additional_authenticated_data": context,
                    "additional_authenticated_data_crc32c": aad_crc,
                }
            )
            if (
                not response.verified_ciphertext_crc32c
                or not response.verified_additional_authenticated_data_crc32c
            ):
                raise EnvelopeError("Cloud KMS rejected request integrity checks")
            plaintext = bytes(response.plaintext)
            if _crc32c(plaintext) != response.plaintext_crc32c:
                raise EnvelopeError("Cloud KMS plaintext integrity check failed")
            return plaintext
        except EnvelopeError:
            raise
        except Exception as exc:
            raise EnvelopeError("Cloud KMS decrypt failed") from exc
