from __future__ import annotations

import logging
import smtplib
import ssl
import time
from collections.abc import Callable
from email.message import (
    EmailMessage as MIMEEmailMessage,
)

from app.core.email_config import (
    EmailConfig,
)
from app.services.mail.base import (
    EmailProvider,
)
from app.services.mail.exceptions import (
    EmailConfigurationError,
)
from app.services.mail.message import (
    EmailMessage,
)
from app.services.mail.result import (
    EmailResult,
)
from app.services.mail.utils import (
    build_mime_message,
)


logger = logging.getLogger(
    __name__,
)


SMTPFactory = Callable[
    ...,
    smtplib.SMTP,
]


class SMTPEmailProvider(
    EmailProvider,
):
    provider_name = "smtp"

    def __init__(
        self,
        config: EmailConfig,
        *,
        smtp_factory: SMTPFactory | None = None,
        smtp_ssl_factory: SMTPFactory | None = None,
        sleep_function: Callable[
            [float],
            None,
        ] = time.sleep,
        clock_function: Callable[
            [],
            float,
        ] = time.perf_counter,
    ) -> None:
        config.validate()

        if config.provider != "smtp":
            raise EmailConfigurationError(
                "SMTPEmailProvider requires "
                "EMAIL_PROVIDER=smtp."
            )

        self.config = config
        self.smtp_factory = (
            smtp_factory
            or smtplib.SMTP
        )
        self.smtp_ssl_factory = (
            smtp_ssl_factory
            or smtplib.SMTP_SSL
        )
        self.sleep_function = (
            sleep_function
        )
        self.clock_function = (
            clock_function
        )

    def _connect(
        self,
    ) -> smtplib.SMTP:
        if self.config.smtp_use_ssl:
            context = (
                ssl.create_default_context()
            )

            return self.smtp_ssl_factory(
                self.config.smtp_host,
                self.config.smtp_port,
                timeout=(
                    self.config
                    .smtp_timeout_seconds
                ),
                context=context,
            )

        client = self.smtp_factory(
            self.config.smtp_host,
            self.config.smtp_port,
            timeout=(
                self.config
                .smtp_timeout_seconds
            ),
        )

        if self.config.smtp_use_tls:
            client.ehlo()
            client.starttls(
                context=(
                    ssl.create_default_context()
                )
            )
            client.ehlo()

        return client

    def _authenticate(
        self,
        client: smtplib.SMTP,
    ) -> None:
        username = (
            self.config.smtp_username
        )
        password = (
            self.config.smtp_password
        )

        if username and password:
            client.login(
                username,
                password,
            )
            return

        if username or password:
            raise EmailConfigurationError(
                "Both SMTP username and SMTP "
                "password are required."
            )

    def _deliver(
        self,
        mime_message: MIMEEmailMessage,
        recipients: tuple[str, ...],
    ) -> str | None:
        client = self._connect()

        try:
            self._authenticate(
                client,
            )

            response = client.send_message(
                mime_message,
                to_addrs=list(
                    recipients,
                ),
            )

            if response:
                rejected = ", ".join(
                    sorted(
                        response.keys(),
                    )
                )

                raise smtplib.SMTPRecipientsRefused(
                    response,
                )

            return mime_message.get(
                "Message-ID",
            )
        finally:
            try:
                client.quit()
            except Exception:
                try:
                    client.close()
                except Exception:
                    logger.exception(
                        "Failed to close SMTP "
                        "connection cleanly."
                    )

    def send(
        self,
        message: EmailMessage,
    ) -> EmailResult:
        started_at = self.clock_function()
        last_error: Exception | None = None
        attempts = 0

        mime_message = build_mime_message(
            message,
            self.config,
        )

        for attempt in range(
            1,
            self.config.smtp_retry_count + 1,
        ):
            attempts = attempt

            try:
                message_id = self._deliver(
                    mime_message,
                    message.all_recipients,
                )

                latency_ms = (
                    self.clock_function()
                    - started_at
                ) * 1000

                logger.info(
                    "Email delivered",
                    extra={
                        "provider": (
                            self.provider_name
                        ),
                        "attempts": attempts,
                        "message_id": (
                            message_id
                        ),
                        "recipient_count": len(
                            message.all_recipients
                        ),
                    },
                )

                return EmailResult.delivered(
                    provider=(
                        self.provider_name
                    ),
                    attempts=attempts,
                    latency_ms=latency_ms,
                    message_id=message_id,
                    metadata={
                        "recipient_count": len(
                            message.all_recipients
                        ),
                    },
                )

            except Exception as exc:
                last_error = exc

                logger.warning(
                    "Email delivery attempt "
                    "failed",
                    extra={
                        "provider": (
                            self.provider_name
                        ),
                        "attempt": attempt,
                        "error": str(
                            exc,
                        ),
                    },
                )

                if (
                    attempt
                    < self.config.smtp_retry_count
                ):
                    self.sleep_function(
                        self.config
                        .smtp_retry_delay_seconds
                    )

        latency_ms = (
            self.clock_function()
            - started_at
        ) * 1000

        error_message = (
            str(
                last_error,
            )
            if last_error
            else "Unknown SMTP error."
        )

        logger.error(
            "Email delivery failed",
            extra={
                "provider": (
                    self.provider_name
                ),
                "attempts": attempts,
                "error": error_message,
            },
        )

        return EmailResult.failed(
            provider=self.provider_name,
            attempts=attempts,
            latency_ms=latency_ms,
            error=error_message,
            metadata={
                "error_type": (
                    type(
                        last_error,
                    ).__name__
                    if last_error
                    else None
                ),
                "recipient_count": len(
                    message.all_recipients
                ),
            },
        )
