"""Secret-delivery sidecar writing only to a memory-backed shared volume."""

from __future__ import annotations

import asyncio
import os
import secrets
from pathlib import Path

import httpx


def atomic_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise RuntimeError("secret target may not be a symlink")
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o400)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o400)
    finally:
        temporary.unlink(missing_ok=True)


async def run() -> None:
    broker_url = os.environ["AGENTSHIELD_BROKER_URL"].rstrip("/")
    namespace = os.environ["AGENTSHIELD_SECRET_NAMESPACE"]
    name = os.environ["AGENTSHIELD_SECRET_NAME"]
    target = Path(os.environ.get("AGENTSHIELD_SECRET_PATH", "/run/agentshield/secret"))
    token_path = Path(
        os.environ.get("AGENTSHIELD_TOKEN_PATH", "/var/run/secrets/agentshield/token")
    )
    ca_path = os.environ["AGENTSHIELD_BROKER_CA_FILE"]
    interval = max(5.0, float(os.environ.get("AGENTSHIELD_POLL_SECONDS", "30")))
    maximum = int(os.environ.get("AGENTSHIELD_MAX_SECRET_BYTES", "1048576"))
    generation: str | None = None
    async with httpx.AsyncClient(
        verify=ca_path,
        timeout=httpx.Timeout(10.0),
        follow_redirects=False,
    ) as http:
        while True:
            token = token_path.read_text(encoding="utf-8").strip()  # noqa: ASYNC240
            response = await http.get(
                f"{broker_url}/v1/secrets/{namespace}/{name}",
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
            if len(response.content) > maximum:
                raise RuntimeError("broker response exceeds configured maximum")
            observed = response.headers.get("X-AgentShield-Generation")
            if observed != generation:
                atomic_write(target, response.content)
                generation = observed
            await asyncio.sleep(interval)


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
