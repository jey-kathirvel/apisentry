from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from app.services.auth.constants import (
    EMAIL_VERIFICATION_EXPIRY_HOURS,
)
from app.services.auth.exceptions import (
    AuthenticationValidationError,
    DuplicateEmailError,
)
from app.services.auth.password import (
    hash_password,
)
from app.services.auth.token import (
    generate_verification_token,
    hash_token,
)
from app.services.auth.validators import (
    validate_email,
    validate_name,
)


class SignupRepository(Protocol):
    def email_exists(
        self,
        email: str,
    ) -> bool:
        ...

    def create_user(
        self,
        *,
        full_name: str,
        email: str,
        password_hash: str,
        verification_token_hash: str,
        verification_token_expires_at: datetime,
    ) -> Any:
        ...


@dataclass(slots=True, frozen=True)
class SignupResult:
    user: Any
    verification_token: str
    verification_token_expires_at: datetime


class SignupService:
    def __init__(
        self,
        repository: SignupRepository,
    ) -> None:
        self.repository = repository

    def register(
        self,
        *,
        full_name: str,
        email: str,
        password: str,
        password_confirmation: str,
        terms_accepted: bool,
    ) -> SignupResult:
        normalized_name = validate_name(
            full_name,
        )

        normalized_email = validate_email(
            email,
        )

        if not terms_accepted:
            raise AuthenticationValidationError(
                "You must accept the terms and conditions."
            )

        if password != password_confirmation:
            raise AuthenticationValidationError(
                "Passwords do not match."
            )

        if self.repository.email_exists(
            normalized_email,
        ):
            raise DuplicateEmailError(
                (
                    "An account already exists with "
                    "this email address."
                )
            )

        password_hash = hash_password(
            password,
        )

        verification_token = (
            generate_verification_token()
        )

        verification_token_hash = hash_token(
            verification_token,
        )

        expires_at = (
            datetime.now(
                timezone.utc,
            )
            + timedelta(
                hours=EMAIL_VERIFICATION_EXPIRY_HOURS,
            )
        )

        user = self.repository.create_user(
            full_name=normalized_name,
            email=normalized_email,
            password_hash=password_hash,
            verification_token_hash=verification_token_hash,
            verification_token_expires_at=expires_at,
        )

        return SignupResult(
            user=user,
            verification_token=verification_token,
            verification_token_expires_at=expires_at,
        )
