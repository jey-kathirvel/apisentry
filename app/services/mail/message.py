from __future__ import annotations

from dataclasses import (
    dataclass,
    field,
)
from pathlib import Path
from typing import Mapping, Sequence

from app.services.mail.exceptions import (
    EmailValidationError,
)


def _normalize_address_list(
    values: Sequence[str] | None,
) -> tuple[str, ...]:
    if not values:
        return ()

    normalized: list[str] = []

    for value in values:
        address = value.strip()

        if not address:
            continue

        if "@" not in address:
            raise EmailValidationError(
                f"Invalid email address: {value}"
            )

        normalized.append(
            address,
        )

    return tuple(
        normalized,
    )


@dataclass(
    frozen=True,
    slots=True,
)
class EmailAttachment:
    filename: str
    content: bytes
    content_type: str = (
        "application/octet-stream"
    )
    content_id: str | None = None
    inline: bool = False

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        content_type: str = (
            "application/octet-stream"
        ),
        content_id: str | None = None,
        inline: bool = False,
    ) -> "EmailAttachment":
        file_path = Path(
            path,
        )

        return cls(
            filename=file_path.name,
            content=file_path.read_bytes(),
            content_type=content_type,
            content_id=content_id,
            inline=inline,
        )


@dataclass(
    frozen=True,
    slots=True,
)
class EmailMessage:
    subject: str
    recipients: tuple[str, ...]

    text_body: str | None = None
    html_body: str | None = None

    sender_email: str | None = None
    sender_name: str | None = None
    reply_to: str | None = None

    cc: tuple[str, ...] = ()
    bcc: tuple[str, ...] = ()

    attachments: tuple[
        EmailAttachment,
        ...
    ] = ()

    headers: Mapping[str, str] = field(
        default_factory=dict,
    )

    def __post_init__(
        self,
    ) -> None:
        subject = self.subject.strip()

        if not subject:
            raise EmailValidationError(
                "Email subject is required."
            )

        recipients = (
            _normalize_address_list(
                self.recipients,
            )
        )
        cc = _normalize_address_list(
            self.cc,
        )
        bcc = _normalize_address_list(
            self.bcc,
        )

        if not recipients:
            raise EmailValidationError(
                "At least one recipient is "
                "required."
            )

        if (
            not self.text_body
            and not self.html_body
        ):
            raise EmailValidationError(
                "Text body or HTML body is "
                "required."
            )

        if (
            self.sender_email
            and "@"
            not in self.sender_email
        ):
            raise EmailValidationError(
                "Invalid sender email address."
            )

        if (
            self.reply_to
            and "@"
            not in self.reply_to
        ):
            raise EmailValidationError(
                "Invalid reply-to address."
            )

        object.__setattr__(
            self,
            "subject",
            subject,
        )
        object.__setattr__(
            self,
            "recipients",
            recipients,
        )
        object.__setattr__(
            self,
            "cc",
            cc,
        )
        object.__setattr__(
            self,
            "bcc",
            bcc,
        )
        object.__setattr__(
            self,
            "attachments",
            tuple(
                self.attachments,
            ),
        )
        object.__setattr__(
            self,
            "headers",
            dict(
                self.headers,
            ),
        )

    @property
    def all_recipients(
        self,
    ) -> tuple[str, ...]:
        values = (
            *self.recipients,
            *self.cc,
            *self.bcc,
        )

        return tuple(
            dict.fromkeys(
                values,
            )
        )
