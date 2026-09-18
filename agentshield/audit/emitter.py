"""Structured audit events with deterministic redaction."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from agentshield.audit.redactor import redact


class AuditEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    action: str
    decision: Literal["allow", "deny", "error"]
    reason: str
    subject_fingerprint: str | None = None
    resource: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class AuditEmitter:
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("agentshield.audit")

    def emit(self, event: AuditEvent) -> None:
        payload = redact(event.model_dump(mode="json"))
        self._logger.info(json.dumps(payload, sort_keys=True, separators=(",", ":")))

