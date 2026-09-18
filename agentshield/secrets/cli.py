"""Secret ingestion CLI: plaintext stays in this process and never enters the API."""

from __future__ import annotations

import asyncio
import base64
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from kubernetes_asyncio import client, config

from agentshield.secrets.envelope import EnvelopeCipher, EnvelopeContext
from agentshield.secrets.kms.gcp import GCPKMSProvider
from agentshield.secrets.kubernetes import GROUP, PLURAL, VERSION, envelope_secret_name

app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False)


def _read_plaintext(source: str, maximum: int) -> bytes:
    value = sys.stdin.buffer.read(maximum + 1) if source == "-" else Path(source).read_bytes()
    if not value or len(value) > maximum:
        raise typer.BadParameter("secret size is outside allowed bounds")
    return value


async def _put(
    namespace: str,
    name: str,
    key_ref: str,
    plaintext: bytes,
    context: str | None,
) -> int:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        await config.load_kube_config(context=context)
    async with client.ApiClient() as api_client:
        custom = client.CustomObjectsApi(api_client)
        core = client.CoreV1Api(api_client)
        resource: dict[str, Any] = await custom.get_namespaced_custom_object(
            GROUP, VERSION, namespace, PLURAL, name
        )
        metadata = resource["metadata"]
        generation = int((resource.get("status") or {}).get("envelopeGeneration", 0)) + 1
        cipher = EnvelopeCipher(GCPKMSProvider(key_ref))
        envelope = await cipher.encrypt(
            plaintext,
            EnvelopeContext(namespace=namespace, name=name, generation=generation),
        )
        secret_name = envelope_secret_name(name)
        annotations = {"agentshield.io/generation": str(generation)}
        owner = client.V1OwnerReference(
            api_version="agentshield.io/v1alpha1",
            kind="AgentSecret",
            name=name,
            uid=metadata["uid"],
            controller=True,
            block_owner_deletion=True,
        )
        body = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=secret_name,
                namespace=namespace,
                annotations=annotations,
                labels={"app.kubernetes.io/managed-by": "agentshield"},
                owner_references=[owner],
            ),
            immutable=False,
            type="agentshield.io/encrypted-envelope",
            data={
                "envelope.json": base64.b64encode(envelope.model_dump_json().encode()).decode()
            },
        )
        try:
            existing = await core.read_namespaced_secret(secret_name, namespace)
            body.metadata.resource_version = existing.metadata.resource_version
            await core.replace_namespaced_secret(secret_name, namespace, body)
        except client.ApiException as exc:
            if exc.status != 404:
                raise
            await core.create_namespaced_secret(namespace, body)
        return generation


@app.command("put")
def put_secret(
    namespace: Annotated[str, typer.Argument(help="AgentSecret namespace")],
    name: Annotated[str, typer.Argument(help="AgentSecret name")],
    key_ref: Annotated[str, typer.Option("--key-ref", help="Full Cloud KMS CryptoKey name")],
    source: Annotated[
        str,
        typer.Option("--file", help="Plaintext file, or - for standard input"),
    ] = "-",
    context: Annotated[str | None, typer.Option("--context", help="kubeconfig context")] = None,
    maximum_bytes: Annotated[int, typer.Option("--max-bytes", min=1, max=1_048_576)] = 65_536,
) -> None:
    """Encrypt and store a new envelope generation."""

    plaintext = bytearray(_read_plaintext(source, maximum_bytes))
    try:
        generation = asyncio.run(_put(namespace, name, key_ref, bytes(plaintext), context))
    finally:
        plaintext[:] = b"\x00" * len(plaintext)
    typer.echo(f"stored encrypted envelope generation {generation}")


if __name__ == "__main__":
    app()

