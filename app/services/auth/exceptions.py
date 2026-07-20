from __future__ import annotations


class AuthenticationError(Exception):
    """Base exception for authentication operations."""


class AuthenticationValidationError(AuthenticationError):
    """Authentication input validation failed."""

    def __init__(
        self,
        message: str,
        *,
        errors: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.errors = errors or [message]


class DuplicateEmailError(AuthenticationError):
    """An account already exists for the supplied email address."""


class WeakPasswordError(AuthenticationValidationError):
    """Password does not satisfy the configured security policy."""


class InvalidTokenError(AuthenticationError):
    """Authentication token is invalid."""


class ExpiredTokenError(InvalidTokenError):
    """Authentication token has expired."""
