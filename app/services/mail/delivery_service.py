from __future__ import annotations

import logging

from app.services.mail.base import EmailProvider
from app.services.mail.exceptions import EmailDeliveryError
from app.services.mail.message import EmailMessage
from app.services.mail.result import EmailResult


logger = logging.getLogger(__name__)


class EmailDeliveryService:
    def __init__(
        self,
        provider: EmailProvider,
        *,
        raise_on_failure: bool = True,
    ) -> None:
        self.provider = provider
        self.raise_on_failure = raise_on_failure

    def send(
        self,
        message: EmailMessage,
    ) -> EmailResult:
        result = self.provider.send(message)

        if result.success:
            return result

        logger.error(
            "Email delivery service received failure result",
            extra={
                "provider": result.provider,
                "attempts": result.attempts,
                "error": result.error,
            },
        )

        if self.raise_on_failure:
            raise EmailDeliveryError(
                result.error or "Email delivery failed.",
                attempts=result.attempts,
                provider=result.provider,
            )

        return result
