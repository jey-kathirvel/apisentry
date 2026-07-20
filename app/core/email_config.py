from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


_TRUE_VALUES = {
    "1",
    "true",
    "yes",
    "on",
    "enabled",
}


def _as_bool(
    value: Any,
    *,
    default: bool = False,
) -> bool:
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    return (
        str(value).strip().lower()
        in _TRUE_VALUES
    )


def _as_int(
    value: Any,
    *,
    default: int,
) -> int:
    if value in {
        None,
        "",
    }:
        return default

    return int(value)


@dataclass(
    frozen=True,
    slots=True,
)
class EmailConfig:
    provider: str = "smtp"

    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None

    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    smtp_timeout_seconds: int = 30
    smtp_retry_count: int = 3
    smtp_retry_delay_seconds: float = 1.0

    default_sender_email: str = (
        "noreply@example.com"
    )
    default_sender_name: str = (
        "API Sentry"
    )

    reply_to: str | None = None

    @classmethod
    def from_environment(
        cls,
    ) -> "EmailConfig":
        return cls(
            provider=(
                os.getenv(
                    "EMAIL_PROVIDER",
                    "smtp",
                )
                .strip()
                .lower()
            ),
            smtp_host=os.getenv(
                "SMTP_HOST",
                "localhost",
            ).strip(),
            smtp_port=_as_int(
                os.getenv(
                    "SMTP_PORT",
                ),
                default=587,
            ),
            smtp_username=(
                os.getenv(
                    "SMTP_USERNAME",
                )
                or None
            ),
            smtp_password=(
                os.getenv(
                    "SMTP_PASSWORD",
                )
                or None
            ),
            smtp_use_tls=_as_bool(
                os.getenv(
                    "SMTP_TLS",
                ),
                default=True,
            ),
            smtp_use_ssl=_as_bool(
                os.getenv(
                    "SMTP_SSL",
                ),
                default=False,
            ),
            smtp_timeout_seconds=_as_int(
                os.getenv(
                    "SMTP_TIMEOUT",
                ),
                default=30,
            ),
            smtp_retry_count=_as_int(
                os.getenv(
                    "SMTP_RETRIES",
                ),
                default=3,
            ),
            smtp_retry_delay_seconds=float(
                os.getenv(
                    "SMTP_RETRY_DELAY",
                    "1",
                )
            ),
            default_sender_email=os.getenv(
                "EMAIL_FROM",
                "noreply@example.com",
            ).strip(),
            default_sender_name=os.getenv(
                "EMAIL_FROM_NAME",
                "API Sentry",
            ).strip(),
            reply_to=(
                os.getenv(
                    "EMAIL_REPLY_TO",
                )
                or None
            ),
        )

    @classmethod
    def from_settings(
        cls,
        settings: Any,
    ) -> "EmailConfig":
        environment_config = (
            cls.from_environment()
        )

        def read(
            *names: str,
            default: Any,
        ) -> Any:
            for name in names:
                if hasattr(
                    settings,
                    name,
                ):
                    value = getattr(
                        settings,
                        name,
                    )

                    if value is not None:
                        return value

            return default

        return cls(
            provider=str(
                read(
                    "email_provider",
                    default=(
                        environment_config.provider
                    ),
                )
            )
            .strip()
            .lower(),
            smtp_host=str(
                read(
                    "smtp_host",
                    default=(
                        environment_config.smtp_host
                    ),
                )
            ).strip(),
            smtp_port=_as_int(
                read(
                    "smtp_port",
                    default=(
                        environment_config.smtp_port
                    ),
                ),
                default=587,
            ),
            smtp_username=read(
                "smtp_username",
                "smtp_user",
                default=(
                    environment_config.smtp_username
                ),
            ),
            smtp_password=read(
                "smtp_password",
                default=(
                    environment_config.smtp_password
                ),
            ),
            smtp_use_tls=_as_bool(
                read(
                    "smtp_use_tls",
                    "smtp_tls",
                    default=(
                        environment_config.smtp_use_tls
                    ),
                ),
                default=True,
            ),
            smtp_use_ssl=_as_bool(
                read(
                    "smtp_use_ssl",
                    "smtp_ssl",
                    default=(
                        environment_config.smtp_use_ssl
                    ),
                ),
                default=False,
            ),
            smtp_timeout_seconds=_as_int(
                read(
                    "smtp_timeout_seconds",
                    "smtp_timeout",
                    default=(
                        environment_config
                        .smtp_timeout_seconds
                    ),
                ),
                default=30,
            ),
            smtp_retry_count=_as_int(
                read(
                    "smtp_retry_count",
                    "smtp_retries",
                    default=(
                        environment_config
                        .smtp_retry_count
                    ),
                ),
                default=3,
            ),
            smtp_retry_delay_seconds=float(
                read(
                    "smtp_retry_delay_seconds",
                    "smtp_retry_delay",
                    default=(
                        environment_config
                        .smtp_retry_delay_seconds
                    ),
                )
            ),
            default_sender_email=str(
                read(
                    "email_from",
                    "default_sender_email",
                    default=(
                        environment_config
                        .default_sender_email
                    ),
                )
            ).strip(),
            default_sender_name=str(
                read(
                    "email_from_name",
                    "default_sender_name",
                    default=(
                        environment_config
                        .default_sender_name
                    ),
                )
            ).strip(),
            reply_to=read(
                "email_reply_to",
                "reply_to",
                default=(
                    environment_config.reply_to
                ),
            ),
        )

    def validate(
        self,
    ) -> None:
        if not self.provider:
            raise ValueError(
                "Email provider is required."
            )

        if self.provider == "smtp":
            if not self.smtp_host:
                raise ValueError(
                    "SMTP host is required."
                )

            if not 1 <= self.smtp_port <= 65535:
                raise ValueError(
                    "SMTP port must be between "
                    "1 and 65535."
                )

            if (
                self.smtp_use_tls
                and self.smtp_use_ssl
            ):
                raise ValueError(
                    "SMTP TLS and SMTP SSL cannot "
                    "both be enabled."
                )

        if self.smtp_timeout_seconds <= 0:
            raise ValueError(
                "SMTP timeout must be greater "
                "than zero."
            )

        if self.smtp_retry_count < 1:
            raise ValueError(
                "SMTP retry count must be at "
                "least one."
            )

        if (
            self.smtp_retry_delay_seconds
            < 0
        ):
            raise ValueError(
                "SMTP retry delay cannot be "
                "negative."
            )

        if (
            not self.default_sender_email
            or "@"
            not in self.default_sender_email
        ):
            raise ValueError(
                "A valid default sender email "
                "is required."
            )
