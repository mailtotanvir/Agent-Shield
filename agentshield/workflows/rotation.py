"""Temporal workflow for durable, reference-only secret rotation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError


@dataclass(frozen=True)
class RotationRequest:
    """Non-secret input persisted in Temporal workflow history."""

    namespace: str
    secret_name: str
    current_generation: int
    idempotency_key: str


@dataclass(frozen=True)
class RotationReservation:
    generation: int
    provider_reference: str


@dataclass(frozen=True)
class PublishedEnvelope:
    generation: int
    ciphertext_digest: str


@dataclass(frozen=True)
class VerificationReceipt:
    generation: int
    receipt_id: str


@dataclass(frozen=True)
class RotationResult:
    generation: int
    ciphertext_digest: str
    verification_receipt: str
    previous_credential_revoked: bool


_RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=10),
    maximum_attempts=4,
    non_retryable_error_types=["RotationPolicyError", "RotationAuthenticationError"],
)
_ACTIVITY_TIMEOUT = timedelta(minutes=2)
_COMPENSATION_RETRY_POLICY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    maximum_interval=timedelta(seconds=5),
    maximum_attempts=8,
)


@workflow.defn
class RotateAgentSecret:
    """Coordinate rotation while keeping secret values out of workflow history."""

    @workflow.run
    async def run(self, request: RotationRequest) -> RotationResult:
        reservation = await workflow.execute_activity(
            "reserve_rotation",
            request,
            result_type=RotationReservation,
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=_RETRY_POLICY,
        )
        try:
            published = await workflow.execute_activity(
                "publish_encrypted_generation",
                reservation,
                result_type=PublishedEnvelope,
                start_to_close_timeout=_ACTIVITY_TIMEOUT,
                retry_policy=_RETRY_POLICY,
            )
            receipt = await workflow.execute_activity(
                "verify_generation",
                published,
                result_type=VerificationReceipt,
                start_to_close_timeout=_ACTIVITY_TIMEOUT,
                retry_policy=_RETRY_POLICY,
            )
        except ActivityError:
            await workflow.execute_activity(
                "disable_candidate_credential",
                reservation,
                start_to_close_timeout=_ACTIVITY_TIMEOUT,
                retry_policy=_COMPENSATION_RETRY_POLICY,
            )
            raise

        await workflow.execute_activity(
            "promote_generation",
            published,
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=_RETRY_POLICY,
        )
        await workflow.execute_activity(
            "revoke_previous_credential",
            request,
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=_COMPENSATION_RETRY_POLICY,
        )
        return RotationResult(
            generation=published.generation,
            ciphertext_digest=published.ciphertext_digest,
            verification_receipt=receipt.receipt_id,
            previous_credential_revoked=True,
        )
