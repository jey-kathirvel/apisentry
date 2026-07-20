import smtplib
from email.message import EmailMessage
from email.utils import formataddr

from app.core.config import settings


class EmailDeliveryError(Exception):
    pass


def send_email(
    recipient: str,
    subject: str,
    html_content: str,
    text_content: str,
) -> None:
    message = EmailMessage()

    message["Subject"] = subject
    message["From"] = formataddr(
        (
            settings.smtp_from_name,
            str(settings.smtp_from_email),
        )
    )
    message["To"] = recipient

    message.set_content(text_content)

    message.add_alternative(
        html_content,
        subtype="html",
    )

    try:
        if settings.smtp_use_ssl:
            with smtplib.SMTP_SSL(
                settings.smtp_host,
                settings.smtp_port,
                timeout=30,
            ) as smtp:
                smtp.login(
                    settings.smtp_username,
                    settings.smtp_password,
                )

                smtp.send_message(message)

        else:
            with smtplib.SMTP(
                settings.smtp_host,
                settings.smtp_port,
                timeout=30,
            ) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()

                smtp.login(
                    settings.smtp_username,
                    settings.smtp_password,
                )

                smtp.send_message(message)

    except Exception as exc:
        raise EmailDeliveryError(
            "Unable to deliver email."
        ) from exc


def send_verification_email(
    recipient: str,
    full_name: str,
    verification_token: str,
) -> None:
    verification_url = (
        f"{settings.frontend_url.rstrip('/')}"
        f"/verify-email?token={verification_token}"
    )

    subject = "Verify your API Sentry account"

    text_content = f"""
Hello {full_name},

Thank you for creating your API Sentry account.

Verify your email address using the following link:

{verification_url}

This verification link expires in
{settings.email_verification_expire_minutes} minutes.

If you did not create this account, you can ignore this email.

API Sentry
""".strip()

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >
    <title>Verify your email</title>
</head>
<body
    style="
        margin:0;
        padding:0;
        background:#f4f7fb;
        font-family:Arial,Helvetica,sans-serif;
        color:#172033;
    "
>
    <table
        role="presentation"
        width="100%"
        cellspacing="0"
        cellpadding="0"
        border="0"
        style="background:#f4f7fb;padding:32px 16px;"
    >
        <tr>
            <td align="center">
                <table
                    role="presentation"
                    width="100%"
                    cellspacing="0"
                    cellpadding="0"
                    border="0"
                    style="
                        max-width:620px;
                        background:#ffffff;
                        border-radius:16px;
                        overflow:hidden;
                        box-shadow:0 12px 32px rgba(15,23,42,.08);
                    "
                >
                    <tr>
                        <td
                            style="
                                padding:30px 36px;
                                background:#172554;
                                color:#ffffff;
                            "
                        >
                            <div
                                style="
                                    font-size:26px;
                                    font-weight:700;
                                "
                            >
                                API Sentry
                            </div>

                            <div
                                style="
                                    margin-top:6px;
                                    font-size:14px;
                                    opacity:.85;
                                "
                            >
                                Secure APIs. Protect every release.
                            </div>
                        </td>
                    </tr>

                    <tr>
                        <td style="padding:38px 36px;">
                            <h1
                                style="
                                    margin:0 0 18px;
                                    font-size:25px;
                                    line-height:1.3;
                                    color:#172033;
                                "
                            >
                                Verify your email address
                            </h1>

                            <p
                                style="
                                    margin:0 0 18px;
                                    font-size:16px;
                                    line-height:1.7;
                                "
                            >
                                Hello {full_name},
                            </p>

                            <p
                                style="
                                    margin:0 0 26px;
                                    font-size:16px;
                                    line-height:1.7;
                                    color:#475569;
                                "
                            >
                                Your API Sentry account has been
                                created. Confirm your email address
                                to activate your account.
                            </p>

                            <table
                                role="presentation"
                                cellspacing="0"
                                cellpadding="0"
                                border="0"
                            >
                                <tr>
                                    <td
                                        style="
                                            background:#2563eb;
                                            border-radius:10px;
                                        "
                                    >
                                        <a
                                            href="{verification_url}"
                                            style="
                                                display:inline-block;
                                                padding:14px 24px;
                                                color:#ffffff;
                                                text-decoration:none;
                                                font-size:16px;
                                                font-weight:700;
                                            "
                                        >
                                            Verify Email Address
                                        </a>
                                    </td>
                                </tr>
                            </table>

                            <p
                                style="
                                    margin:26px 0 0;
                                    font-size:14px;
                                    line-height:1.6;
                                    color:#64748b;
                                "
                            >
                                This link expires in
                                {settings.email_verification_expire_minutes}
                                minutes.
                            </p>

                            <p
                                style="
                                    margin:18px 0 0;
                                    font-size:13px;
                                    line-height:1.6;
                                    color:#94a3b8;
                                    word-break:break-all;
                                "
                            >
                                {verification_url}
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
""".strip()

    send_email(
        recipient=recipient,
        subject=subject,
        html_content=html_content,
        text_content=text_content,
    )


def send_password_reset_email(
    recipient: str,
    full_name: str,
    reset_token: str,
) -> None:
    reset_url = (
        f"{settings.frontend_url.rstrip('/')}"
        f"/reset-password?token={reset_token}"
    )

    subject = "Reset your API Sentry password"

    text_content = f"""
Hello {full_name},

A password reset was requested for your API Sentry account.

Reset your password using the following link:

{reset_url}

This reset link expires in
{settings.password_reset_expire_minutes} minutes.

If you did not request this reset, ignore this email.

API Sentry
""".strip()

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >
    <title>Reset your password</title>
</head>
<body
    style="
        margin:0;
        padding:0;
        background:#f4f7fb;
        font-family:Arial,Helvetica,sans-serif;
        color:#172033;
    "
>
    <table
        role="presentation"
        width="100%"
        cellspacing="0"
        cellpadding="0"
        border="0"
        style="background:#f4f7fb;padding:32px 16px;"
    >
        <tr>
            <td align="center">
                <table
                    role="presentation"
                    width="100%"
                    cellspacing="0"
                    cellpadding="0"
                    border="0"
                    style="
                        max-width:620px;
                        background:#ffffff;
                        border-radius:16px;
                        overflow:hidden;
                        box-shadow:0 12px 32px rgba(15,23,42,.08);
                    "
                >
                    <tr>
                        <td
                            style="
                                padding:30px 36px;
                                background:#172554;
                                color:#ffffff;
                            "
                        >
                            <div
                                style="
                                    font-size:26px;
                                    font-weight:700;
                                "
                            >
                                API Sentry
                            </div>

                            <div
                                style="
                                    margin-top:6px;
                                    font-size:14px;
                                    opacity:.85;
                                "
                            >
                                Secure APIs. Protect every release.
                            </div>
                        </td>
                    </tr>

                    <tr>
                        <td style="padding:38px 36px;">
                            <h1
                                style="
                                    margin:0 0 18px;
                                    font-size:25px;
                                    line-height:1.3;
                                "
                            >
                                Reset your password
                            </h1>

                            <p
                                style="
                                    margin:0 0 18px;
                                    font-size:16px;
                                    line-height:1.7;
                                "
                            >
                                Hello {full_name},
                            </p>

                            <p
                                style="
                                    margin:0 0 26px;
                                    font-size:16px;
                                    line-height:1.7;
                                    color:#475569;
                                "
                            >
                                Use the button below to create a new
                                password for your API Sentry account.
                            </p>

                            <table
                                role="presentation"
                                cellspacing="0"
                                cellpadding="0"
                                border="0"
                            >
                                <tr>
                                    <td
                                        style="
                                            background:#2563eb;
                                            border-radius:10px;
                                        "
                                    >
                                        <a
                                            href="{reset_url}"
                                            style="
                                                display:inline-block;
                                                padding:14px 24px;
                                                color:#ffffff;
                                                text-decoration:none;
                                                font-size:16px;
                                                font-weight:700;
                                            "
                                        >
                                            Reset Password
                                        </a>
                                    </td>
                                </tr>
                            </table>

                            <p
                                style="
                                    margin:26px 0 0;
                                    font-size:14px;
                                    line-height:1.6;
                                    color:#64748b;
                                "
                            >
                                This link expires in
                                {settings.password_reset_expire_minutes}
                                minutes.
                            </p>

                            <p
                                style="
                                    margin:18px 0 0;
                                    font-size:13px;
                                    line-height:1.6;
                                    color:#94a3b8;
                                    word-break:break-all;
                                "
                            >
                                {reset_url}
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
""".strip()

    send_email(
        recipient=recipient,
        subject=subject,
        html_content=html_content,
        text_content=text_content,
    )
