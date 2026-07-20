from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.services.auth.constants import (
    EMAIL_MAX_LENGTH,
    MAX_NAME_LENGTH,
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
)
from app.services.auth.validators import (
    normalize_email,
    normalize_name,
)


class SignupRequest(BaseModel):
    full_name: str = Field(
        min_length=2,
        max_length=MAX_NAME_LENGTH,
    )

    email: str = Field(
        min_length=3,
        max_length=EMAIL_MAX_LENGTH,
    )

    password: str = Field(
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_LENGTH,
    )

    password_confirmation: str = Field(
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_LENGTH,
    )

    terms_accepted: bool

    @model_validator(mode="after")
    def normalize_and_validate(
        self,
    ) -> "SignupRequest":
        self.full_name = normalize_name(
            self.full_name,
        )

        self.email = normalize_email(
            self.email,
        )

        if self.password != self.password_confirmation:
            raise ValueError(
                "Passwords do not match."
            )

        if not self.terms_accepted:
            raise ValueError(
                "Terms and conditions must be accepted."
            )

        return self


class SignupResponse(BaseModel):
    id: int | str
    full_name: str
    email: str
    email_verified: bool = False
    created_at: Any | None = None
