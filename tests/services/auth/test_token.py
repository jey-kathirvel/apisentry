from __future__ import annotations

from app.services.auth.token import (
    compare_token_hash,
    generate_api_key,
    generate_password_reset_token,
    generate_session_token,
    generate_verification_token,
    hash_token,
)


def test_verification_tokens_are_unique() -> None:
    tokens = {
        generate_verification_token()
        for _ in range(100)
    }

    assert len(tokens) == 100


def test_password_reset_tokens_are_unique() -> None:
    first = generate_password_reset_token()
    second = generate_password_reset_token()

    assert first != second


def test_session_token_is_not_empty() -> None:
    assert len(
        generate_session_token()
    ) >= 40


def test_api_key_has_prefix() -> None:
    assert generate_api_key().startswith(
        "aps_",
    )


def test_hash_token_is_deterministic() -> None:
    assert (
        hash_token("sample-token")
        == hash_token("sample-token")
    )


def test_compare_token_hash_accepts_match() -> None:
    token = "sample-token"

    assert compare_token_hash(
        token,
        hash_token(token),
    )


def test_compare_token_hash_rejects_mismatch() -> None:
    assert not compare_token_hash(
        "sample-token",
        hash_token("other-token"),
    )
