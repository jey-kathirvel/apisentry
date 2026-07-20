from __future__ import annotations

from typing import Any

from app.core.email_config import (
    EmailConfig,
)
from app.services.mail.message import (
    EmailMessage,
)
from app.services.mail.smtp_provider import (
    SMTPEmailProvider,
)


class FakeSMTP:
    instances: list["FakeSMTP"] = []
    failures_remaining = 0

    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: int,
        **kwargs: Any,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.kwargs = kwargs

        self.ehlo_count = 0
        self.starttls_called = False
        self.login_credentials: (
            tuple[str, str] | None
        ) = None
        self.sent_message = None
        self.to_addrs = None
        self.quit_called = False
        self.close_called = False

        self.__class__.instances.append(
            self,
        )

    def ehlo(
        self,
    ) -> None:
        self.ehlo_count += 1

    def starttls(
        self,
        *,
        context: Any,
    ) -> None:
        self.starttls_called = True

    def login(
        self,
        username: str,
        password: str,
    ) -> None:
        self.login_credentials = (
            username,
            password,
        )

    def send_message(
        self,
        message: Any,
        *,
        to_addrs: list[str],
    ) -> dict[str, Any]:
        if (
            self.__class__
            .failures_remaining
            > 0
        ):
            self.__class__.failures_remaining -= 1

            raise ConnectionError(
                "Temporary SMTP failure"
            )

        self.sent_message = message
        self.to_addrs = to_addrs

        return {}

    def quit(
        self,
    ) -> None:
        self.quit_called = True

    def close(
        self,
    ) -> None:
        self.close_called = True


def reset_fake_smtp() -> None:
    FakeSMTP.instances = []
    FakeSMTP.failures_remaining = 0


def build_config(
    *,
    retries: int = 3,
) -> EmailConfig:
    return EmailConfig(
        provider="smtp",
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_username="smtp-user",
        smtp_password="smtp-password",
        smtp_use_tls=True,
        smtp_use_ssl=False,
        smtp_timeout_seconds=10,
        smtp_retry_count=retries,
        smtp_retry_delay_seconds=0,
        default_sender_email=(
            "noreply@apisentry.example"
        ),
        default_sender_name=(
            "API Sentry"
        ),
    )


def test_smtp_provider_delivers_email() -> None:
    reset_fake_smtp()

    provider = SMTPEmailProvider(
        build_config(),
        smtp_factory=FakeSMTP,
        sleep_function=lambda _: None,
    )

    result = provider.send(
        EmailMessage(
            subject="Verify your email",
            recipients=(
                "user@example.com",
            ),
            text_body=(
                "Verification instructions"
            ),
            html_body=(
                "<p>Verification "
                "instructions</p>"
            ),
        )
    )

    assert result.success is True
    assert result.attempts == 1
    assert result.provider == "smtp"
    assert result.message_id is not None

    instance = FakeSMTP.instances[0]

    assert instance.host == (
        "smtp.example.com"
    )
    assert instance.port == 587
    assert instance.timeout == 10
    assert instance.starttls_called is True
    assert instance.ehlo_count == 2
    assert instance.login_credentials == (
        "smtp-user",
        "smtp-password",
    )
    assert instance.to_addrs == [
        "user@example.com",
    ]
    assert instance.quit_called is True


def test_smtp_provider_retries_and_succeeds() -> None:
    reset_fake_smtp()

    FakeSMTP.failures_remaining = 2

    provider = SMTPEmailProvider(
        build_config(
            retries=3,
        ),
        smtp_factory=FakeSMTP,
        sleep_function=lambda _: None,
    )

    result = provider.send(
        EmailMessage(
            subject="Retry Test",
            recipients=(
                "user@example.com",
            ),
            text_body="Retry body",
        )
    )

    assert result.success is True
    assert result.attempts == 3
    assert len(
        FakeSMTP.instances,
    ) == 3


def test_smtp_provider_returns_failed_result() -> None:
    reset_fake_smtp()

    FakeSMTP.failures_remaining = 5

    provider = SMTPEmailProvider(
        build_config(
            retries=2,
        ),
        smtp_factory=FakeSMTP,
        sleep_function=lambda _: None,
    )

    result = provider.send(
        EmailMessage(
            subject="Failure Test",
            recipients=(
                "user@example.com",
            ),
            text_body="Failure body",
        )
    )

    assert result.success is False
    assert result.attempts == 2
    assert result.error == (
        "Temporary SMTP failure"
    )
    assert (
        result.metadata["error_type"]
        == "ConnectionError"
    )


def test_smtp_provider_includes_cc_and_bcc() -> None:
    reset_fake_smtp()

    provider = SMTPEmailProvider(
        build_config(),
        smtp_factory=FakeSMTP,
        sleep_function=lambda _: None,
    )

    result = provider.send(
        EmailMessage(
            subject="Recipients Test",
            recipients=(
                "primary@example.com",
            ),
            cc=(
                "copy@example.com",
            ),
            bcc=(
                "hidden@example.com",
            ),
            text_body="Recipients body",
        )
    )

    assert result.success is True

    instance = FakeSMTP.instances[0]

    assert instance.to_addrs == [
        "primary@example.com",
        "copy@example.com",
        "hidden@example.com",
    ]

    assert (
        instance.sent_message.get(
            "Bcc",
        )
        is None
    )
