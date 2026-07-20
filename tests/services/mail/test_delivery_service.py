from __future__ import annotations

import pytest

from app.services.mail.base import EmailProvider
from app.services.mail.delivery_service import EmailDeliveryService
from app.services.mail.exceptions import EmailDeliveryError
from app.services.mail.message import EmailMessage
from app.services.mail.result import EmailResult


class SuccessfulProvider(EmailProvider):
    provider_name = "test"

    def send(
        self,
        message: EmailMessage,
    ) -> EmailResult:
        return EmailResult.delivered(
            provider=self.provider_name,
            attempts=1,
            latency_ms=1.5,
            message_id="message-1",
        )


class FailingProvider(EmailProvider):
    provider_name = "test"

    def send(
        self,
        message: EmailMessage,
    ) -> EmailResult:
        return EmailResult.failed(
            provider=self.provider_name,
            attempts=3,
            latency_ms=10.0,
            error="Delivery rejected",
        )


def build_message() -> EmailMessage:
    return EmailMessage(
        subject="Test",
        recipients=("user@example.com",),
        text_body="Test body",
    )


def test_delivery_service_returns_success() -> None:
    service = EmailDeliveryService(
        SuccessfulProvider(),
    )

    result = service.send(
        build_message(),
    )

    assert result.success is True
    assert result.message_id == "message-1"


def test_delivery_service_raises_on_failure() -> None:
    service = EmailDeliveryService(
        FailingProvider(),
        raise_on_failure=True,
    )

    with pytest.raises(
        EmailDeliveryError,
        match="Delivery rejected",
    ) as exc_info:
        service.send(
            build_message(),
        )

    assert exc_info.value.provider == "test"
    assert exc_info.value.attempts == 3


def test_delivery_service_can_return_failure() -> None:
    service = EmailDeliveryService(
        FailingProvider(),
        raise_on_failure=False,
    )

    result = service.send(
        build_message(),
    )

    assert result.success is False
    assert result.error == "Delivery rejected"
