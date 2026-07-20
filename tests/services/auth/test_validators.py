from __future__ import annotations

import pytest

from app.services.auth.exceptions import (
    AuthenticationValidationError,
)
from app.services.auth.validators import (
    normalize_email,
    normalize_name,
    validate_email,
    validate_name,
)


def test_normalize_email() -> None:
    assert (
        normalize_email(
            "  USER@Example.COM  ",
        )
        == "user@example.com"
    )


def test_validate_email_returns_normalized_email() -> None:
    assert (
        validate_email(
            "  USER@Example.COM  ",
        )
        == "user@example.com"
    )


@pytest.mark.parametrize(
    "email",
    [
        "",
        "invalid",
        "user@",
        "@example.com",
        "user@example",
    ],
)
def test_invalid_emails_are_rejected(
    email: str,
) -> None:
    with pytest.raises(
        AuthenticationValidationError,
    ):
        validate_email(
            email,
        )


def test_normalize_name() -> None:
    assert (
        normalize_name(
            "  Jey   Kathirvel  ",
        )
        == "Jey Kathirvel"
    )


def test_validate_name_returns_normalized_name() -> None:
    assert (
        validate_name(
            "  Jey   Kathirvel  ",
        )
        == "Jey Kathirvel"
    )


@pytest.mark.parametrize(
    "name",
    [
        "",
        "J",
    ],
)
def test_invalid_names_are_rejected(
    name: str,
) -> None:
    with pytest.raises(
        AuthenticationValidationError,
    ):
        validate_name(
            name,
        )
