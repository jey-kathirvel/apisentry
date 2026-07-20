from __future__ import annotations

import re

from app.services.auth.constants import (
    EMAIL_MAX_LENGTH,
    MAX_NAME_LENGTH,
    MIN_NAME_LENGTH,
)
from app.services.auth.exceptions import (
    AuthenticationValidationError,
)

_EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9-]+"
    r"(?:\.[A-Za-z0-9-]+)+$"
)

_CONTROL_CHARACTER_PATTERN = re.compile(
    r"[\x00-\x1f\x7f]",
)


def normalize_email(
    email: str,
) -> str:
    if not isinstance(email, str):
        raise AuthenticationValidationError(
            "Email address must be a string."
        )

    return email.strip().lower()


def validate_email(
    email: str,
) -> str:
    normalized_email = normalize_email(
        email,
    )

    errors: list[str] = []

    if not normalized_email:
        errors.append(
            "Email address is required."
        )

    if len(normalized_email) > EMAIL_MAX_LENGTH:
        errors.append(
            (
                "Email address must not exceed "
                f"{EMAIL_MAX_LENGTH} characters."
            )
        )

    if (
        normalized_email
        and not _EMAIL_PATTERN.fullmatch(
            normalized_email,
        )
    ):
        errors.append(
            "Enter a valid email address."
        )

    if _CONTROL_CHARACTER_PATTERN.search(
        normalized_email,
    ):
        errors.append(
            "Email address contains invalid characters."
        )

    if errors:
        raise AuthenticationValidationError(
            "Email validation failed.",
            errors=errors,
        )

    return normalized_email


def normalize_name(
    name: str,
) -> str:
    if not isinstance(name, str):
        raise AuthenticationValidationError(
            "Full name must be a string."
        )

    return " ".join(
        name.strip().split()
    )


def validate_name(
    name: str,
) -> str:
    normalized_name = normalize_name(
        name,
    )

    errors: list[str] = []

    if not normalized_name:
        errors.append(
            "Full name is required."
        )

    if (
        normalized_name
        and len(normalized_name) < MIN_NAME_LENGTH
    ):
        errors.append(
            (
                "Full name must contain at least "
                f"{MIN_NAME_LENGTH} characters."
            )
        )

    if len(normalized_name) > MAX_NAME_LENGTH:
        errors.append(
            (
                "Full name must not exceed "
                f"{MAX_NAME_LENGTH} characters."
            )
        )

    if _CONTROL_CHARACTER_PATTERN.search(
        normalized_name,
    ):
        errors.append(
            "Full name contains invalid characters."
        )

    if errors:
        raise AuthenticationValidationError(
            "Name validation failed.",
            errors=errors,
        )

    return normalized_name
