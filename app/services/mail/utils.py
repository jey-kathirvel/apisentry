from __future__ import annotations

from email.message import (
    EmailMessage as MIMEEmailMessage,
)
from email.utils import (
    formataddr,
    make_msgid,
)
from mimetypes import guess_type

from app.core.email_config import (
    EmailConfig,
)
from app.services.mail.message import (
    EmailAttachment,
    EmailMessage,
)


def split_content_type(
    content_type: str,
) -> tuple[str, str]:
    normalized = (
        content_type.strip().lower()
    )

    if "/" not in normalized:
        return (
            "application",
            "octet-stream",
        )

    maintype, subtype = (
        normalized.split(
            "/",
            1,
        )
    )

    return (
        maintype,
        subtype,
    )


def resolve_attachment_content_type(
    attachment: EmailAttachment,
) -> str:
    if (
        attachment.content_type
        != "application/octet-stream"
    ):
        return attachment.content_type

    guessed_type, _ = guess_type(
        attachment.filename,
    )

    return (
        guessed_type
        or attachment.content_type
    )


def build_mime_message(
    message: EmailMessage,
    config: EmailConfig,
) -> MIMEEmailMessage:
    mime_message = MIMEEmailMessage()

    sender_email = (
        message.sender_email
        or config.default_sender_email
    )

    sender_name = (
        message.sender_name
        or config.default_sender_name
    )

    mime_message["Subject"] = (
        message.subject
    )
    mime_message["From"] = formataddr(
        (
            sender_name,
            sender_email,
        )
    )
    mime_message["To"] = ", ".join(
        message.recipients,
    )
    mime_message["Message-ID"] = make_msgid(
        domain=(
            sender_email.split(
                "@",
                1,
            )[1]
        ),
    )

    if message.cc:
        mime_message["Cc"] = ", ".join(
            message.cc,
        )

    reply_to = (
        message.reply_to
        or config.reply_to
    )

    if reply_to:
        mime_message["Reply-To"] = (
            reply_to
        )

    for key, value in message.headers.items():
        forbidden_headers = {
            "to",
            "from",
            "subject",
            "cc",
            "bcc",
            "message-id",
        }

        if (
            key.strip().lower()
            in forbidden_headers
        ):
            continue

        mime_message[key] = value

    if message.text_body:
        mime_message.set_content(
            message.text_body,
        )
    else:
        mime_message.set_content(
            "This email requires an "
            "HTML-compatible email client."
        )

    if message.html_body:
        mime_message.add_alternative(
            message.html_body,
            subtype="html",
        )

    for attachment in message.attachments:
        content_type = (
            resolve_attachment_content_type(
                attachment,
            )
        )

        maintype, subtype = (
            split_content_type(
                content_type,
            )
        )

        if attachment.inline:
            related_part = (
                mime_message.get_payload()[-1]
                if message.html_body
                else mime_message
            )

            related_part.add_related(
                attachment.content,
                maintype=maintype,
                subtype=subtype,
                filename=(
                    attachment.filename
                ),
                cid=(
                    attachment.content_id
                    or make_msgid()
                ),
                disposition="inline",
            )
        else:
            mime_message.add_attachment(
                attachment.content,
                maintype=maintype,
                subtype=subtype,
                filename=(
                    attachment.filename
                ),
            )

    return mime_message
