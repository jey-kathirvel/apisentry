from __future__ import annotations

import hashlib
import hmac
import secrets

from app.services.auth.constants import (
    API_KEY_BYTES,
    PASSWORD_RESET_TOKEN_BYTES,
    SESSION_TOKEN_BYTES,
    VERIFICATION_TOKEN_BYTES,
)


def generate_verification_token() -> str:
    return secrets.token_urlsafe(
        VERIFICATION_TOKEN_BYTES,
    )


def generate_password_reset_token() -> str:
    return secrets.token_urlsafe(
        PASSWORD_RESET_TOKEN_BYTES,
    )


def generate_session_token() -> str:
    return secrets.token_urlsafe(
        SESSION_TOKEN_BYTES,
    )


def generate_api_key() -> str:
    return (
        "aps_"
        + secrets.token_urlsafe(
            API_KEY_BYTES,
        )
    )


def hash_token(
    token: str,
) -> str:
    if not token:
        raise ValueError(
            "Token is required.",
        )

    return hashlib.sha256(
        token.encode("utf-8"),
    ).hexdigest()


def compare_token_hash(
    token: str,
    expected_hash: str,
) -> bool:
    if not token or not expected_hash:
        return False

    actual_hash = hash_token(
        token,
    )

    return hmac.compare_digest(
        actual_hash,
        expected_hash,
    )
