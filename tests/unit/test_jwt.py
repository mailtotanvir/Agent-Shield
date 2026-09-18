from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from agentshield.errors import AlgorithmForbiddenError, KeyResolutionError
from agentshield.session.jwks import JWKSCache
from agentshield.session.validator import JWTValidator, ValidationPolicy


def make_key(kid: str = "key-1") -> tuple[ec.EllipticCurvePrivateKey, dict[str, object]]:
    private = ec.generate_private_key(ec.SECP256R1())
    public_jwk = jwt.PyJWK.from_dict(
        jwt.algorithms.ECAlgorithm.to_jwk(private.public_key(), as_dict=True)
    )._jwk_data
    return private, {**public_jwk, "kid": kid, "use": "sig", "alg": "ES256"}


@pytest.mark.asyncio
async def test_validates_asymmetric_token_and_scopes() -> None:
    private, jwk = make_key()

    async def fetch() -> dict[str, object]:
        return {"keys": [jwk]}

    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "iss": "https://issuer.example",
            "sub": "agent-1",
            "aud": "api",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "scope": "read write",
            "cnf": {"jkt": "thumbprint"},
        },
        private,
        algorithm="ES256",
        headers={"kid": "key-1"},
    )
    claims = await JWTValidator(JWKSCache(fetch)).validate(
        token,
        ValidationPolicy(
            issuer="https://issuer.example",
            audience="api",
            required_scopes=frozenset({"read"}),
            require_dpop_binding=True,
        ),
    )
    assert claims.subject == "agent-1"
    assert claims.confirmation_jkt == "thumbprint"


@pytest.mark.asyncio
async def test_rejects_hs256_before_key_resolution() -> None:
    async def fetch() -> dict[str, object]:
        raise AssertionError("must not fetch keys")

    token = jwt.encode({"sub": "agent"}, "s" * 32, algorithm="HS256", headers={"kid": "x"})
    with pytest.raises(AlgorithmForbiddenError):
        await JWTValidator(JWKSCache(fetch)).validate(
            token, ValidationPolicy(issuer="https://issuer.example", audience="api")
        )


@pytest.mark.asyncio
async def test_duplicate_kid_is_rejected() -> None:
    _private, jwk = make_key()

    async def fetch() -> dict[str, object]:
        return {"keys": [jwk, jwk]}

    with pytest.raises(KeyResolutionError, match="duplicate"):
        await JWKSCache(fetch).resolve("key-1", "ES256")
