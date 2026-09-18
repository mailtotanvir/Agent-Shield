"""Google OIDC configuration, deliberately separate from IAP validation."""

from agentshield.identity.oidc import OIDCProvider


def google_accounts_provider() -> OIDCProvider:
    return OIDCProvider(
        issuer="https://accounts.google.com",
        authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint="https://oauth2.googleapis.com/token",  # nosec B106
        jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
        revocation_endpoint="https://oauth2.googleapis.com/revoke",
    )
