"""Key-management provider adapters."""

from agentshield.secrets.kms.base import KMSProvider
from agentshield.secrets.kms.fake import FakeKMSProvider

__all__ = ["FakeKMSProvider", "KMSProvider"]

