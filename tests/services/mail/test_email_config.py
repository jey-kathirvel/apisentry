from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.core.email_config import (
    EmailConfig,
)


def test_default_email_config_is_valid() -> None:
    config = EmailConfig()

    config.validate()

    assert config.provider == "smtp"
    assert config.smtp_port == 587
    assert config.smtp_use_tls is True
    assert config.smtp_use_ssl is False


def test_tls_and_ssl_cannot_both_be_enabled() -> None:
    config = EmailConfig(
        smtp_use_tls=True,
        smtp_use_ssl=True,
    )

    with pytest.raises(
        ValueError,
        match="cannot both be enabled",
    ):
        config.validate()


def test_invalid_retry_count_is_rejected() -> None:
    config = EmailConfig(
        smtp_retry_count=0,
    )

    with pytest.raises(
        ValueError,
        match="at least one",
    ):
        config.validate()


def test_environment_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "EMAIL_PROVIDER",
        "smtp",
    )
    monkeypatch.setenv(
        "SMTP_HOST",
        "smtp.example.com",
    )
    monkeypatch.setenv(
        "SMTP_PORT",
        "465",
    )
    monkeypatch.setenv(
        "SMTP_TLS",
        "false",
    )
    monkeypatch.setenv(
        "SMTP_SSL",
        "true",
    )
    monkeypatch.setenv(
        "SMTP_RETRIES",
        "4",
    )
    monkeypatch.setenv(
        "EMAIL_FROM",
        "security@example.com",
    )

    config = (
        EmailConfig.from_environment()
    )

    assert config.smtp_host == (
        "smtp.example.com"
    )
    assert config.smtp_port == 465
    assert config.smtp_use_tls is False
    assert config.smtp_use_ssl is True
    assert config.smtp_retry_count == 4
    assert config.default_sender_email == (
        "security@example.com"
    )


def test_application_settings_map_ssl_and_sender_fields() -> None:
    config = EmailConfig.from_settings(
        SimpleNamespace(
            smtp_host="smtp.example.com",
            smtp_port=465,
            smtp_username="user",
            smtp_password="password",
            smtp_use_ssl=True,
            smtp_from_email="noreply@example.com",
            smtp_from_name="API Sentry",
        )
    )

    config.validate()

    assert config.smtp_use_ssl is True
    assert config.smtp_use_tls is False
    assert config.default_sender_email == "noreply@example.com"
    assert config.default_sender_name == "API Sentry"
