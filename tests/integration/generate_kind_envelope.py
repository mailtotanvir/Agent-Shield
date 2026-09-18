"""Generate synthetic kind evidence without persisting plaintext."""

import argparse
import asyncio
import base64
import hashlib
import secrets
from pathlib import Path

from agentshield.secrets.envelope import EnvelopeCipher, EnvelopeContext
from agentshield.secrets.kms.fake import FakeKMSProvider


async def generate(output: Path, digest_output: Path, key_b64: str, key_ref: str) -> None:
    plaintext = bytearray(b"agentshield-kind-canary-" + secrets.token_bytes(32))
    key = base64.b64decode(key_b64, validate=True)
    try:
        envelope = await EnvelopeCipher(FakeKMSProvider(key, key_ref=key_ref)).encrypt(
            bytes(plaintext),
            EnvelopeContext(namespace="agents", name="llm-key", generation=1),
        )
        output.write_text(envelope.model_dump_json(), encoding="utf-8")  # noqa: ASYNC240
        digest_output.write_text(  # noqa: ASYNC240
            hashlib.sha256(plaintext).hexdigest(), encoding="utf-8"
        )
    finally:
        plaintext[:] = b"\x00" * len(plaintext)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--digest-output", type=Path, required=True)
    parser.add_argument("--key-b64", required=True)
    parser.add_argument("--key-ref", required=True)
    args = parser.parse_args()
    asyncio.run(generate(args.output, args.digest_output, args.key_b64, args.key_ref))


if __name__ == "__main__":
    main()
