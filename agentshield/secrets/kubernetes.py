"""Narrow Kubernetes adapters for broker authentication and envelope reads."""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Protocol

from kubernetes_asyncio import client

from agentshield.errors import EnvelopeError, SecretAccessDeniedError
from agentshield.secrets.envelope import EncryptedEnvelope
from agentshield.secrets.models import AllowedServiceAccount, SecretAccessPolicy, WorkloadIdentity

GROUP = "agentshield.io"
VERSION = "v1alpha1"
PLURAL = "agentsecrets"
TOKEN_AUDIENCE = "agentshield-broker"  # nosec B105


def envelope_secret_name(name: str) -> str:
    digest = hashlib.sha256(name.encode()).hexdigest()[:10]
    return f"agentshield-envelope-{name[:210]}-{digest}"


class TokenReviewer(Protocol):
    async def review(self, token: str) -> WorkloadIdentity: ...


class SecretReader(Protocol):
    async def read(
        self, namespace: str, name: str, identity: WorkloadIdentity
    ) -> tuple[EncryptedEnvelope, SecretAccessPolicy]: ...


class KubernetesTokenReviewer:
    def __init__(self, api: client.AuthenticationV1Api) -> None:
        self._api = api

    async def review(self, token: str) -> WorkloadIdentity:
        body = client.V1TokenReview(
            spec=client.V1TokenReviewSpec(token=token, audiences=[TOKEN_AUDIENCE])
        )
        try:
            result = await self._api.create_token_review(body)
        except Exception as exc:
            raise SecretAccessDeniedError("workload authentication unavailable") from exc
        status = result.status
        if not status or not status.authenticated or TOKEN_AUDIENCE not in (status.audiences or []):
            raise SecretAccessDeniedError("workload token is not authenticated")
        user = status.user
        if not user or not user.username:
            raise SecretAccessDeniedError("workload token has no identity")
        parts = user.username.split(":")
        if len(parts) != 4 or parts[:2] != ["system", "serviceaccount"]:
            raise SecretAccessDeniedError("workload token subject is not a service account")
        extra = user.extra or {}
        pod_name = _single_extra(extra, "authentication.kubernetes.io/pod-name")
        pod_uid = _single_extra(extra, "authentication.kubernetes.io/pod-uid")
        return WorkloadIdentity(
            namespace=parts[2],
            service_account=parts[3],
            pod_name=pod_name,
            pod_uid=pod_uid,
        )


def _single_extra(extra: dict[str, Any], key: str) -> str:
    values = extra.get(key)
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str):
        raise SecretAccessDeniedError("workload token is not bound to a pod")
    return values[0]


class KubernetesSecretReader:
    def __init__(self, core: client.CoreV1Api, custom: client.CustomObjectsApi) -> None:
        self._core = core
        self._custom = custom

    async def read(
        self, namespace: str, name: str, identity: WorkloadIdentity
    ) -> tuple[EncryptedEnvelope, SecretAccessPolicy]:
        if identity.namespace != namespace:
            raise SecretAccessDeniedError("cross-namespace secret access is denied")
        try:
            pod = await self._core.read_namespaced_pod(identity.pod_name, namespace)
            resource = await self._custom.get_namespaced_custom_object(
                GROUP, VERSION, namespace, PLURAL, name
            )
        except Exception as exc:
            raise SecretAccessDeniedError("secret policy could not be resolved") from exc
        if (
            not pod.metadata
            or pod.metadata.uid != identity.pod_uid
            or not pod.spec
            or pod.spec.service_account_name != identity.service_account
        ):
            raise SecretAccessDeniedError("pod identity does not match bound token")
        policy = _parse_policy(resource, namespace)
        policy.authorize(identity, pod.metadata.labels or {})
        try:
            secret = await self._core.read_namespaced_secret(envelope_secret_name(name), namespace)
            encoded = (secret.data or {})["envelope.json"]
            envelope = EncryptedEnvelope.model_validate_json(
                base64.b64decode(encoded, validate=True)
            )
        except Exception as exc:
            raise EnvelopeError("encrypted envelope is unavailable or invalid") from exc
        if envelope.context.namespace != namespace or envelope.context.name != name:
            raise EnvelopeError("envelope resource identity mismatch")
        return envelope, policy


def _parse_policy(resource: dict[str, Any], namespace: str) -> SecretAccessPolicy:
    try:
        access = resource["spec"]["access"]
        accounts = tuple(
            AllowedServiceAccount(
                name=item["name"],
                namespace=item.get("namespace", namespace),
            )
            for item in access["allowedServiceAccounts"]
        )
        scoped = access.get("scopedTo") or {}
        match_labels = scoped.get("matchLabels", {}) if isinstance(scoped, dict) else {}
        return SecretAccessPolicy(
            allowed_service_accounts=accounts,
            match_labels=match_labels,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SecretAccessDeniedError("AgentSecret access policy is invalid") from exc
