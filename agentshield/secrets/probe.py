"""Integration helper for proving broker denial without exposing a token."""

import asyncio
import os
from pathlib import Path

import httpx


async def probe() -> None:
    token = Path(os.environ["AGENTSHIELD_TOKEN_PATH"]).read_text().strip()  # noqa: ASYNC240
    async with httpx.AsyncClient(
        verify=os.environ["AGENTSHIELD_BROKER_CA_FILE"],
        timeout=10,
        follow_redirects=False,
    ) as client:
        response = await client.get(
            os.environ["AGENTSHIELD_SECRET_URL"],
            headers={"Authorization": f"Bearer {token}"},
        )
    if response.status_code != 403:
        raise RuntimeError(f"expected denial, received status {response.status_code}")
    print("verified unauthorized workload denial status=403")


def main() -> None:
    asyncio.run(probe())


if __name__ == "__main__":
    main()
