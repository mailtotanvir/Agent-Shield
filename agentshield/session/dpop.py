"""RFC 9449 DPoP proof generation and validation."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from agentshield.errors import ReplayDetectedError, TokenValidationError
from agentshield.session.revocation import ExpiringStore


def _b64uint(value: int) -> str:
    size = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


def _b64digest(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()


def normalize_htu(uri: str) -> str:
    parsed = urlsplit(uri)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ValueError("DPoP URI must be absolute HTTP(S)")
    host = parsed.hostname.lower()
    port = parsed.port
    include_port = port is not None and not (
        (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)
    )
    authority = f"{host}:{port}" if include_port else host
    return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", "", ""))


class DPoPKey:
    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        self._key = private_key or ec.generate_private_key(ec.SECP256R1())

    @property
    def public_jwk(self) -> dict[str, str]:
        numbers = self._key.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", "x": _b64uint(numbers.x), "y": _b64uint(numbers.y)}

    @property
    def thumbprint(self) -> str:
        canonical = json.dumps(self.public_jwk, sort_keys=True, separators=(",", ":")).encode()
        return _b64digest(canonical)

    def proof(
        self,
        method: str,
        uri: str,
        *,
        access_token: str | None = None,
        nonce: str | None = None,
        now: datetime | None = None,
    ) -> str:
        issued = int((now or datetime.now(UTC)).timestamp())
        claims: dict[str, object] = {
            "jti": secrets.token_urlsafe(24),
            "htm": method.upper(),
            "htu": normalize_htu(uri),
            "iat": issued,
        }
        if access_token is not None:
            claims["ath"] = _b64digest(access_token.encode())
        if nonce is not None:
            claims["nonce"] = nonce
        return jwt.encode(
            claims,
            self._key,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": self.public_jwk},
        )


class DPoPValidator:
    def __init__(self, replay_store: ExpiringStore, *, window_seconds: int = 120) -> None:
        self._store = replay_store
        self._window = window_seconds

    async def validate(
        self,
        proof: str,
        *,
        method: str,
        uri: str,
        expected_jkt: str,
        access_token: str | None = None,
        nonce: str | None = None,
        now: datetime | None = None,
    ) -> None:
        try:
            header = jwt.get_unverified_header(proof)
            if header.get("typ", "").lower() != "dpop+jwt" or header.get("alg") != "ES256":
                raise TokenValidationError("invalid DPoP header")
            jwk = header.get("jwk")
            if not isinstance(jwk, dict) or "d" in jwk:
                raise TokenValidationError("invalid DPoP public key")
            canonical = json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode()
            if _b64digest(canonical) != expected_jkt:
                raise TokenValidationError("DPoP key thumbprint mismatch")
            key = jwt.PyJWK.from_dict(jwk, algorithm="ES256").key
            claims = jwt.decode(
                proof,
                key,
                algorithms=["ES256"],
                options={"require": ["jti", "htm", "htu", "iat"], "verify_aud": False},
            )
        except TokenValidationError:
            raise
        except jwt.PyJWTError as exc:
            raise TokenValidationError("DPoP proof validation failed") from exc
        current = int((now or datetime.now(UTC)).timestamp())
        if not isinstance(claims["iat"], int) or abs(current - claims["iat"]) > self._window:
            raise TokenValidationError("DPoP proof is outside the accepted time window")
        if claims["htm"] != method.upper() or claims["htu"] != normalize_htu(uri):
            raise TokenValidationError("DPoP request binding mismatch")
        if access_token is not None and claims.get("ath") != _b64digest(access_token.encode()):
            raise TokenValidationError("DPoP access-token hash mismatch")
        if nonce is not None and claims.get("nonce") != nonce:
            raise TokenValidationError("DPoP nonce mismatch")
        jti = claims["jti"]
        unique = isinstance(jti, str) and await self._store.add_once(
            f"dpop:{expected_jkt}:{jti}", self._window
        )
        if not unique:
            raise ReplayDetectedError("DPoP proof was replayed")
