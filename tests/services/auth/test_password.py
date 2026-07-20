from __future__ import annotations

import pytest

from app.services.auth.exceptions import (
    WeakPasswordError,
)
from app.services.auth.password import (
    hash_password,
    validate_password_strength,
    verify_password,
)


def test_strong_password_has_no_errors() -> None:
    assert (
        validate_password_strength(
            "SecurePass1!",
        )
        == []
    )


@pytest.mark.parametrize(
    ("password", "expected_message"),
    [
        (
            "Aa1!",
            "at least 8 characters",
        ),
        (
            "securepass1!",
            "uppercase",
        ),
        (
            "SECUREPASS1!",
            "lowercase",
        ),
        (
            "SecurePass!",
            "number",
        ),
        (
            "SecurePass1",
            "special character",
        ),
        (
            "Secure Pass1!",
            "whitespace",
        ),
    ],
)
def test_password_validation_rules(
    password: str,
    expected_message: str,
) -> None:
    errors = validate_password_strength(
        password,
    )

    assert any(
        expected_message in error
        for error in errors
    )


def test_hash_password_creates_non_plaintext_hash() -> None:
    password = "SecurePass1!"

    password_hash = hash_password(
        password,
    )

    assert password_hash != password
    assert password_hash.startswith(
        (
            "$2a$",
            "$2b$",
            "$2y$",
        )
    )


def test_verify_password_accepts_correct_password() -> None:
    password_hash = hash_password(
        "SecurePass1!",
    )

    assert verify_password(
        "SecurePass1!",
        password_hash,
    )


def test_verify_password_rejects_wrong_password() -> None:
    password_hash = hash_password(
        "SecurePass1!",
    )

    assert not verify_password(
        "WrongPass1!",
        password_hash,
    )


def test_hash_password_rejects_weak_password() -> None:
    with pytest.raises(
        WeakPasswordError,
    ):
        hash_password(
            "weak",
        )
