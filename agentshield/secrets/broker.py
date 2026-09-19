"""Authenticated in-cluster secret delivery broker."""

from __future__ import annotations

import asyncio
import base64
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Response
from kubernetes_asyncio import client, config

from agentshield.audit.emitter import AuditEmitter, AuditEvent
from agentshield.audit.redactor import fingerprint
from agentshield.errors import EnvelopeError, SecretAccessDeniedError
from agentshield.secrets.envelope import EnvelopeCipher
from agentshield.secrets.kms.base import KMSProvider
from agentshield.secrets.kms.fake import FakeKMSProvider
from agentshield.secrets.kms.gcp import GCPKMSProvider
from agentshield.secrets.kubernetes import (
    KubernetesSecretReader,
    KubernetesTokenReviewer,
    SecretReader,
    TokenReviewer,
)

logger = logging.getLogger("uvicorn.error")


class SecretBroker:
    def __init__(
        self,
        reviewer: TokenReviewer,
        reader: SecretReader,
        cipher: EnvelopeCipher,
        *,
        audit: AuditEmitter | None = None,
        max_concurrency: int = 32,
    ) -> None:
        self._reviewer = reviewer
        self._reader = reader
        self._cipher = cipher
        self._audit = audit or AuditEmitter()
        self._capacity = asyncio.Semaphore(max_concurrency)

    async def deliver(self, namespace: str, name: str, authorization: str) -> tuple[bytes, int]:
        if not authorization.startswith("Bearer ") or len(authorization) > 20_000:
            raise SecretAccessDeniedError("missing or invalid workload authorization")
        token = authorization.removeprefix("Bearer ")
        identity = await self._reviewer.review(token)
        resource = f"{namespace}/{name}"
        try:
            async with self._capacity:
                envelope, _policy = await self._reader.read(namespace, name, identity)
                plaintext = await self._cipher.decrypt(envelope)
            self._audit.emit(
                AuditEvent(
                    action="secret.deliver",
                    decision="allow",
                    reason="policy_allowed",
                    subject_fingerprint=fingerprint(
                        f"{identity.namespace}:{identity.service_account}:{identity.pod_uid}"
                    ),
                    resource=resource,
                    details={"generation": envelope.context.generation},
                )
            )
            return plaintext, envelope.context.generation
        except (SecretAccessDeniedError, EnvelopeError) as exc:
            self._audit.emit(
                AuditEvent(
                    action="secret.deliver",
                    decision="deny",
                    reason=exc.code,
                    subject_fingerprint=fingerprint(
                        f"{identity.namespace}:{identity.service_account}:{identity.pod_uid}"
                    ),
                    resource=resource,
                )
            )
            logger.warning(
                "secret delivery failed: code=%s reason=%s resource=%s",
                exc.code,
                str(exc),
                resource,
            )
            raise


def kms_from_environment() -> KMSProvider:
    environment = os.environ.get("AGENTSHIELD_ENVIRONMENT", "production")
    provider = os.environ.get("AGENTSHIELD_KMS_PROVIDER", "gcp")
    key_ref = os.environ["AGENTSHIELD_KMS_KEY_REF"]
    if provider == "gcp":
        return GCPKMSProvider(key_ref)
    if provider == "fake" and environment in {"development", "test"}:
        encoded = os.environ.get("AGENTSHIELD_FAKE_KMS_KEY_B64", "")
        try:
            key = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise RuntimeError("fake KMS key is invalid") from exc
        if len(key) != 32:
            raise RuntimeError("fake KMS key must decode to 32 bytes")
        return FakeKMSProvider(key, key_ref=key_ref)
    raise RuntimeError("unsupported or unsafe KMS provider configuration")


def create_app(broker: SecretBroker) -> FastAPI:
    app = FastAPI(
        title="AgentShield Secret Broker",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/healthz", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/secrets/{namespace}/{name}", include_in_schema=False)
    async def get_secret(
        namespace: str,
        name: str,
        authorization: str = Header(default="", max_length=20_000),
    ) -> Response:
        try:
            plaintext, generation = await broker.deliver(namespace, name, authorization)
        except SecretAccessDeniedError as exc:
            raise HTTPException(status_code=403, detail=exc.code) from None
        except EnvelopeError as exc:
            raise HTTPException(status_code=503, detail=exc.code) from None
        return Response(
            content=plaintext,
            media_type="application/octet-stream",
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-AgentShield-Generation": str(generation),
                "X-Content-Type-Options": "nosniff",
            },
        )

    return app


@asynccontextmanager
async def _kubernetes_clients() -> AsyncIterator[tuple[client.ApiClient, SecretBroker]]:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        await config.load_kube_config()
    api_client = client.ApiClient()
    core = client.CoreV1Api(api_client)
    custom = client.CustomObjectsApi(api_client)
    auth = client.AuthenticationV1Api(api_client)
    cipher = EnvelopeCipher(kms_from_environment())
    broker = SecretBroker(
        KubernetesTokenReviewer(auth), KubernetesSecretReader(core, custom), cipher
    )
    try:
        yield api_client, broker
    finally:
        await api_client.close()


def main() -> None:
    cert = os.environ.get("AGENTSHIELD_TLS_CERT_FILE")
    key = os.environ.get("AGENTSHIELD_TLS_KEY_FILE")
    if not cert or not key:
        raise RuntimeError("broker TLS certificate and key are required")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with _kubernetes_clients() as (_api, broker):
            app.state.broker = broker
            yield

    bootstrap = FastAPI(lifespan=lifespan, docs_url=None, openapi_url=None)

    @bootstrap.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @bootstrap.get("/v1/secrets/{namespace}/{name}")
    async def deliver(
        namespace: str,
        name: str,
        authorization: str = Header(default="", max_length=20_000),
    ) -> Response:
        broker: SecretBroker = bootstrap.state.broker
        try:
            payload, generation = await broker.deliver(namespace, name, authorization)
        except SecretAccessDeniedError as exc:
            raise HTTPException(status_code=403, detail=exc.code) from None
        except EnvelopeError as exc:
            raise HTTPException(status_code=503, detail=exc.code) from None
        return Response(
            payload,
            media_type="application/octet-stream",
            headers={"Cache-Control": "no-store", "X-AgentShield-Generation": str(generation)},
        )

    uvicorn.run(
        bootstrap,
        host="0.0.0.0",  # nosec B104
        port=8443,
        ssl_certfile=cert,
        ssl_keyfile=key,
    )


if __name__ == "__main__":
    main()
