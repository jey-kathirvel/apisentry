from __future__ import annotations

import pytest

from app.services.mail.exceptions import (
    EmailValidationError,
)
from app.services.mail.message import (
    EmailAttachment,
    EmailMessage,
)


def test_email_message_normalizes_addresses() -> None:
    message = EmailMessage(
        subject=" Test Email ",
        recipients=(
            " user@example.com ",
        ),
        cc=(
            "copy@example.com",
        ),
        bcc=(
            "hidden@example.com",
        ),
        text_body="Test body",
    )

    assert message.subject == "Test Email"
    assert message.recipients == (
        "user@example.com",
    )
    assert message.all_recipients == (
        "user@example.com",
        "copy@example.com",
        "hidden@example.com",
    )


def test_email_requires_recipient() -> None:
    with pytest.raises(
        EmailValidationError,
        match="At least one recipient",
    ):
        EmailMessage(
            subject="Test",
            recipients=(),
            text_body="Test body",
        )


def test_email_requires_body() -> None:
    with pytest.raises(
        EmailValidationError,
        match="Text body or HTML body",
    ):
        EmailMessage(
            subject="Test",
            recipients=(
                "user@example.com",
            ),
        )


def test_attachment_model() -> None:
    attachment = EmailAttachment(
        filename="report.json",
        content=b'{"status":"ok"}',
        content_type="application/json",
    )

    assert attachment.filename == (
        "report.json"
    )
    assert attachment.content_type == (
        "application/json"
    )
