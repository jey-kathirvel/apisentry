from __future__ import annotations


class EmailError(Exception):
    pass


class EmailConfigurationError(
    EmailError,
):
    pass


class EmailValidationError(
    EmailError,
):
    pass


class EmailProviderError(
    EmailError,
):
    pass


class UnsupportedEmailProviderError(
    EmailConfigurationError,
):
    pass


class EmailDeliveryError(
    EmailProviderError,
):
    def __init__(
        self,
        message: str,
        *,
        attempts: int,
        provider: str,
        original_error: Exception | None = None,
    ) -> None:
        super().__init__(
            message,
        )

        self.attempts = attempts
        self.provider = provider
        self.original_error = original_error
