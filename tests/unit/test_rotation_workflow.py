from __future__ import annotations

import hashlib
import uuid

import pytest
from temporalio import activity
from temporalio.client import WorkflowFailureError
from temporalio.exceptions import ApplicationError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from agentshield.workflows.rotation import (
    PublishedEnvelope,
    RotateAgentSecret,
    RotationRequest,
    RotationReservation,
    VerificationReceipt,
)


class FakeRotationActivities:
    def __init__(self, canary: str, *, fail_verification: bool = False) -> None:
        self._canary = canary
        self._fail_verification = fail_verification
        self.reserve_attempts = 0
        self.disabled = False
        self.promoted = False
        self.revoked = False

    @activity.defn(name="reserve_rotation")
    async def reserve_rotation(self, request: RotationRequest) -> RotationReservation:
        self.reserve_attempts += 1
        if self.reserve_attempts < 2:
            raise ApplicationError("provider temporarily unavailable")
        return RotationReservation(
            generation=request.current_generation + 1,
            provider_reference="provider-record/rotation-2",
        )

    @activity.defn(name="publish_encrypted_generation")
    async def publish_encrypted_generation(
        self, reservation: RotationReservation
    ) -> PublishedEnvelope:
        return PublishedEnvelope(
            generation=reservation.generation,
            ciphertext_digest=hashlib.sha256(b"fake-envelope-v1").hexdigest(),
        )

    @activity.defn(name="verify_generation")
    async def verify_generation(self, published: PublishedEnvelope) -> VerificationReceipt:
        if self._fail_verification:
            raise ApplicationError("delivery digest mismatch", non_retryable=True)
        return VerificationReceipt(generation=published.generation, receipt_id="verify/2")

    @activity.defn(name="disable_candidate_credential")
    async def disable_candidate_credential(self, reservation: RotationReservation) -> None:
        self.disabled = True

    @activity.defn(name="promote_generation")
    async def promote_generation(self, published: PublishedEnvelope) -> None:
        self.promoted = True

    @activity.defn(name="revoke_previous_credential")
    async def revoke_previous_credential(self, request: RotationRequest) -> None:
        self.revoked = True

    def registered(self) -> list[object]:
        return [
            self.reserve_rotation,
            self.publish_encrypted_generation,
            self.verify_generation,
            self.disable_candidate_credential,
            self.promote_generation,
            self.revoke_previous_credential,
        ]


def request() -> RotationRequest:
    return RotationRequest(
        namespace="agents",
        secret_name="llm-key",
        current_generation=1,
        idempotency_key="rotation-request-2",
    )


@pytest.mark.asyncio
async def test_rotation_retries_and_history_excludes_plaintext() -> None:
    canary = "CANARY-PLAINTEXT-MUST-NOT-ENTER-TEMPORAL"
    activities = FakeRotationActivities(canary)
    workflow_id = f"rotation-{uuid.uuid4()}"
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue=workflow_id,
            workflows=[RotateAgentSecret],
            activities=activities.registered(),
        ):
            result = await environment.client.execute_workflow(
                RotateAgentSecret.run,
                request(),
                id=workflow_id,
                task_queue=workflow_id,
            )
            history = await environment.client.get_workflow_handle(workflow_id).fetch_history()

    assert result.generation == 2
    assert result.ciphertext_digest == hashlib.sha256(b"fake-envelope-v1").hexdigest()
    assert result.verification_receipt == "verify/2"
    assert result.previous_credential_revoked
    assert activities.reserve_attempts == 2
    assert activities.promoted
    assert activities.revoked
    assert not activities.disabled
    assert canary not in str(history)


@pytest.mark.asyncio
async def test_rotation_compensates_failed_verification() -> None:
    activities = FakeRotationActivities("failed-canary", fail_verification=True)
    workflow_id = f"rotation-{uuid.uuid4()}"
    async with await WorkflowEnvironment.start_time_skipping() as environment:
        async with Worker(
            environment.client,
            task_queue=workflow_id,
            workflows=[RotateAgentSecret],
            activities=activities.registered(),
        ):
            with pytest.raises(WorkflowFailureError):
                await environment.client.execute_workflow(
                    RotateAgentSecret.run,
                    request(),
                    id=workflow_id,
                    task_queue=workflow_id,
                )

    assert activities.disabled
    assert not activities.promoted
    assert not activities.revoked
