from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from typing import Any

import pytest

from app.services.auth.exceptions import (
    AuthenticationValidationError,
    DuplicateEmailError,
    WeakPasswordError,
)
from app.services.auth.signup_service import (
    SignupService,
)
from app.services.auth.token import (
    compare_token_hash,
)


class FakeSignupRepository:
    def __init__(
        self,
        *,
        existing_emails: set[str] | None = None,
    ) -> None:
        self.existing_emails = (
            existing_emails or set()
        )
        self.created_payload: (
            dict[str, Any] | None
        ) = None

    def email_exists(
        self,
        email: str,
    ) -> bool:
        return email in self.existing_emails

    def create_user(
        self,
        *,
        full_name: str,
        email: str,
        password_hash: str,
        verification_token_hash: str,
        verification_token_expires_at: datetime,
    ) -> Any:
        self.created_payload = {
            "full_name": full_name,
            "email": email,
            "password_hash": password_hash,
            "verification_token_hash": (
                verification_token_hash
            ),
            "verification_token_expires_at": (
                verification_token_expires_at
            ),
        }

        return SimpleNamespace(
            id=1,
            full_name=full_name,
            email=email,
            is_email_verified=False,
        )


def test_register_normalizes_user_data() -> None:
    repository = FakeSignupRepository()
    service = SignupService(
        repository,
    )

    result = service.register(
        full_name="  Jey   Kathirvel  ",
        email="  JEY@EXAMPLE.COM ",
        password="SecurePass1!",
        password_confirmation="SecurePass1!",
        terms_accepted=True,
    )

    assert result.user.full_name == (
        "Jey Kathirvel"
    )
    assert result.user.email == (
        "jey@example.com"
    )

    assert repository.created_payload is not None
    assert (
        repository.created_payload["full_name"]
        == "Jey Kathirvel"
    )
    assert (
        repository.created_payload["email"]
        == "jey@example.com"
    )


def test_register_hashes_password() -> None:
    repository = FakeSignupRepository()
    service = SignupService(
        repository,
    )

    service.register(
        full_name="Jey Kathirvel",
        email="jey@example.com",
        password="SecurePass1!",
        password_confirmation="SecurePass1!",
        terms_accepted=True,
    )

    assert repository.created_payload is not None

    password_hash = (
        repository.created_payload[
            "password_hash"
        ]
    )

    assert password_hash != "SecurePass1!"
    assert password_hash.startswith(
        (
            "$2a$",
            "$2b$",
            "$2y$",
        )
    )


def test_register_returns_raw_verification_token() -> None:
    repository = FakeSignupRepository()
    service = SignupService(
        repository,
    )

    result = service.register(
        full_name="Jey Kathirvel",
        email="jey@example.com",
        password="SecurePass1!",
        password_confirmation="SecurePass1!",
        terms_accepted=True,
    )

    assert result.verification_token
    assert repository.created_payload is not None

    stored_hash = (
        repository.created_payload[
            "verification_token_hash"
        ]
    )

    assert compare_token_hash(
        result.verification_token,
        stored_hash,
    )


def test_register_sets_verification_expiry() -> None:
    repository = FakeSignupRepository()
    service = SignupService(
        repository,
    )

    result = service.register(
        full_name="Jey Kathirvel",
        email="jey@example.com",
        password="SecurePass1!",
        password_confirmation="SecurePass1!",
        terms_accepted=True,
    )

    assert result.verification_token_expires_at
    assert repository.created_payload is not None

    assert (
        repository.created_payload[
            "verification_token_expires_at"
        ]
        == result.verification_token_expires_at
    )


def test_register_rejects_duplicate_email() -> None:
    repository = FakeSignupRepository(
        existing_emails={
            "jey@example.com",
        },
    )

    service = SignupService(
        repository,
    )

    with pytest.raises(
        DuplicateEmailError,
    ):
        service.register(
            full_name="Jey Kathirvel",
            email="JEY@EXAMPLE.COM",
            password="SecurePass1!",
            password_confirmation="SecurePass1!",
            terms_accepted=True,
        )


def test_register_rejects_unaccepted_terms() -> None:
    repository = FakeSignupRepository()
    service = SignupService(
        repository,
    )

    with pytest.raises(
        AuthenticationValidationError,
    ):
        service.register(
            full_name="Jey Kathirvel",
            email="jey@example.com",
            password="SecurePass1!",
            password_confirmation="SecurePass1!",
            terms_accepted=False,
        )


def test_register_rejects_password_mismatch() -> None:
    repository = FakeSignupRepository()
    service = SignupService(
        repository,
    )

    with pytest.raises(
        AuthenticationValidationError,
    ):
        service.register(
            full_name="Jey Kathirvel",
            email="jey@example.com",
            password="SecurePass1!",
            password_confirmation=(
                "DifferentPass1!"
            ),
            terms_accepted=True,
        )


def test_register_rejects_weak_password() -> None:
    repository = FakeSignupRepository()
    service = SignupService(
        repository,
    )

    with pytest.raises(
        WeakPasswordError,
    ):
        service.register(
            full_name="Jey Kathirvel",
            email="jey@example.com",
            password="weak",
            password_confirmation="weak",
            terms_accepted=True,
        )


def test_repository_is_not_called_on_validation_error() -> None:
    repository = FakeSignupRepository()
    service = SignupService(
        repository,
    )

    with pytest.raises(
        AuthenticationValidationError,
    ):
        service.register(
            full_name="J",
            email="invalid-email",
            password="SecurePass1!",
            password_confirmation="SecurePass1!",
            terms_accepted=True,
        )

    assert repository.created_payload is None
