"""Kopf reconciler for AgentSecret policy and envelope status."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import kopf
from kubernetes_asyncio import client

from agentshield.secrets.kubernetes import envelope_secret_name


def validate_spec(spec: dict[str, Any]) -> None:
    encryption = spec.get("encryption")
    access = spec.get("access")
    if not isinstance(encryption, dict) or encryption.get("provider") != "gcp-kms":
        raise kopf.PermanentError("initial release requires encryption.provider=gcp-kms")
    key_ref = encryption.get("keyRef")
    if not isinstance(key_ref, str) or not key_ref.startswith("projects/"):
        raise kopf.PermanentError("encryption.keyRef must be a full GCP KMS resource name")
    if not isinstance(access, dict) or not access.get("allowedServiceAccounts"):
        raise kopf.PermanentError("at least one allowed ServiceAccount is required")


async def reconcile(
    *,
    name: str,
    namespace: str,
    uid: str,
    generation: int,
    spec: dict[str, Any],
    core: Any,
) -> dict[str, Any]:
    validate_spec(spec)
    envelope_name = envelope_secret_name(name)
    try:
        secret = await core.read_namespaced_secret(envelope_name, namespace)
        annotation_generation = int(
            (secret.metadata.annotations or {}).get("agentshield.io/generation", "0")
        )
        ready = annotation_generation >= 1 and "envelope.json" in (secret.data or {})
    except client.ApiException as exc:
        if exc.status != 404:
            raise kopf.TemporaryError("could not inspect encrypted envelope", delay=5) from exc
        ready = False
        annotation_generation = 0
    condition = {
        "type": "Ready",
        "status": "True" if ready else "False",
        "reason": "EnvelopeAvailable" if ready else "AwaitingEncryptedValue",
        "message": (
            "encrypted envelope is ready"
            if ready
            else f"run agentshield secret put {namespace} {name}"
        ),
        "observedGeneration": generation,
        "lastTransitionTime": datetime.now(UTC).isoformat(),
    }
    return {
        "observedGeneration": generation,
        "envelopeSecret": envelope_name,
        "envelopeGeneration": annotation_generation,
        "conditions": [condition],
        "resourceUID": uid,
    }


@kopf.on.create("agentshield.io", "v1alpha1", "agentsecrets")
@kopf.on.update("agentshield.io", "v1alpha1", "agentsecrets")
@kopf.on.resume("agentshield.io", "v1alpha1", "agentsecrets")  # type: ignore[arg-type]
async def reconcile_agent_secret(
    name: str,
    namespace: str,
    uid: str,
    meta: dict[str, Any],
    spec: dict[str, Any],
    patch: dict[str, Any],
    **_: Any,
) -> None:
    core = client.CoreV1Api()
    status = await reconcile(
        name=name,
        namespace=namespace,
        uid=uid,
        generation=int(meta.get("generation", 1)),
        spec=spec,
        core=core,
    )
    patch["status"] = status


@kopf.timer(  # type: ignore[arg-type]
    "agentshield.io", "v1alpha1", "agentsecrets", interval=300.0, sharp=True
)
async def mark_rotation_due(
    spec: dict[str, Any],
    status: dict[str, Any],
    patch: dict[str, Any],
    **_: Any,
) -> None:
    rotation = spec.get("rotation") or {}
    if not rotation.get("enabled"):
        return
    interval_hours = int(rotation.get("intervalHours", 24))
    last_value = status.get("lastCredentialRotationTime")
    if not last_value:
        patch.setdefault("status", {})["rotationDue"] = True
        return
    try:
        last = datetime.fromisoformat(last_value)
    except ValueError:
        patch.setdefault("status", {})["rotationDue"] = True
        return
    patch.setdefault("status", {})["rotationDue"] = (
        datetime.now(UTC) >= last + timedelta(hours=interval_hours)
    )
