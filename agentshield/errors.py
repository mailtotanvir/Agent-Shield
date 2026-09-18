"""Stable, non-sensitive error taxonomy."""


class AgentShieldError(Exception):
    """Base error safe to catch at the package boundary."""

    code = "agentshield_error"


class ConfigurationError(AgentShieldError):
    code = "configuration_error"


class OAuthProtocolError(AgentShieldError):
    code = "oauth_protocol_error"


class TokenValidationError(AgentShieldError):
    code = "token_validation_error"


class AlgorithmForbiddenError(TokenValidationError):
    code = "algorithm_forbidden"


class KeyResolutionError(TokenValidationError):
    code = "key_resolution_error"


class PolicyDeniedError(AgentShieldError):
    code = "policy_denied"


class ReplayDetectedError(PolicyDeniedError):
    code = "replay_detected"


class VaultError(AgentShieldError):
    code = "vault_error"


class SecretAccessDeniedError(AgentShieldError):
    code = "secret_access_denied"


class EnvelopeError(AgentShieldError):
    code = "envelope_error"

