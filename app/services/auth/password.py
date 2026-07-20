from __future__ import annotations

import re
from functools import lru_cache
from typing import Protocol

from app.services.auth.constants import (
    BCRYPT_ROUNDS,
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
)
from app.services.auth.exceptions import WeakPasswordError


class _PasswordHasher(Protocol):
    def hash(self, password: str) -> str:
        ...

    def verify(self, password: str, password_hash: str) -> bool:
        ...


class _PasslibBcryptHasher:
    def __init__(self) -> None:
        from passlib.context import CryptContext

        self._context = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt__rounds=BCRYPT_ROUNDS,
        )

    def hash(self, password: str) -> str:
        return self._context.hash(password)

    def verify(
        self,
        password: str,
        password_hash: str,
    ) -> bool:
        try:
            return bool(
                self._context.verify(
                    password,
                    password_hash,
                )
            )
        except (TypeError, ValueError):
            return False


class _BcryptPackageHasher:
    def __init__(self) -> None:
        import bcrypt

        self._bcrypt = bcrypt

    def hash(self, password: str) -> str:
        encoded = password.encode("utf-8")

        return self._bcrypt.hashpw(
            encoded,
            self._bcrypt.gensalt(
                rounds=BCRYPT_ROUNDS,
            ),
        ).decode("utf-8")

    def verify(
        self,
        password: str,
        password_hash: str,
    ) -> bool:
        try:
            return bool(
                self._bcrypt.checkpw(
                    password.encode("utf-8"),
                    password_hash.encode("utf-8"),
                )
            )
        except (
            TypeError,
            ValueError,
            UnicodeError,
        ):
            return False


@lru_cache(maxsize=1)
def _get_password_hasher() -> _PasswordHasher:
    try:
        return _PasslibBcryptHasher()
    except ImportError:
        try:
            return _BcryptPackageHasher()
        except ImportError as exc:
            raise RuntimeError(
                "Password hashing requires either "
                "'passlib[bcrypt]' or 'bcrypt'."
            ) from exc


def validate_password_strength(
    password: str,
) -> list[str]:
    errors: list[str] = []

    if not isinstance(password, str):
        return [
            "Password must be a string.",
        ]

    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(
            (
                "Password must contain at least "
                f"{PASSWORD_MIN_LENGTH} characters."
            )
        )

    if len(password) > PASSWORD_MAX_LENGTH:
        errors.append(
            (
                "Password must not exceed "
                f"{PASSWORD_MAX_LENGTH} characters."
            )
        )

    if not re.search(r"[A-Z]", password):
        errors.append(
            "Password must contain at least one uppercase letter."
        )

    if not re.search(r"[a-z]", password):
        errors.append(
            "Password must contain at least one lowercase letter."
        )

    if not re.search(r"\d", password):
        errors.append(
            "Password must contain at least one number."
        )

    if not re.search(r"[^A-Za-z0-9\s]", password):
        errors.append(
            "Password must contain at least one special character."
        )

    if re.search(r"\s", password):
        errors.append(
            "Password must not contain whitespace."
        )

    return errors


def assert_password_strength(
    password: str,
) -> None:
    errors = validate_password_strength(
        password,
    )

    if errors:
        raise WeakPasswordError(
            "Password does not meet the security requirements.",
            errors=errors,
        )


def hash_password(
    password: str,
) -> str:
    assert_password_strength(
        password,
    )

    return _get_password_hasher().hash(
        password,
    )


def verify_password(
    plain_password: str,
    password_hash: str,
) -> bool:
    if not plain_password or not password_hash:
        return False

    return _get_password_hasher().verify(
        plain_password,
        password_hash,
    )
