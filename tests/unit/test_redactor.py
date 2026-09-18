from agentshield.audit.redactor import redact


def test_redacts_nested_secrets_and_fingerprints_identity() -> None:
    result = redact(
        {
            "access_token": "top-secret",
            "claims": {"sub": "person-1", "role": "admin"},
            "message": "failed with Bearer ey.secret.value",
        }
    )
    assert result["access_token"] == "[REDACTED]"
    assert result["claims"]["sub"].startswith("sha256:")
    assert result["claims"]["role"] == "admin"
    assert "ey.secret.value" not in result["message"]

