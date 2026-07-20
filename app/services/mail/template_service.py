from __future__ import annotations

from datetime import datetime
from typing import Any

from app.services.mail.message import EmailMessage
from app.services.mail.template_renderer import (
    EmailTemplateRenderer,
)


class EmailTemplateService:
    def __init__(
        self,
        renderer: EmailTemplateRenderer,
    ) -> None:
        self.renderer = renderer

    def verification_email(
        self,
        *,
        recipient: str,
        full_name: str,
        verification_url: str,
        expires_at: datetime,
    ) -> EmailMessage:
        rendered = self.renderer.render(
            template_name="verify_email",
            context={
                "full_name": full_name,
                "verification_url": verification_url,
                "expires_at": expires_at,
            },
        )

        return EmailMessage(
            subject=rendered.subject,
            recipients=(recipient,),
            text_body=rendered.text_body,
            html_body=rendered.html_body,
        )

    def password_reset_email(
        self,
        *,
        recipient: str,
        full_name: str,
        reset_url: str,
        expires_at: datetime,
    ) -> EmailMessage:
        rendered = self.renderer.render(
            template_name="reset_password",
            context={
                "full_name": full_name,
                "reset_url": reset_url,
                "expires_at": expires_at,
            },
        )

        return EmailMessage(
            subject=rendered.subject,
            recipients=(recipient,),
            text_body=rendered.text_body,
            html_body=rendered.html_body,
        )

    def welcome_email(
        self,
        *,
        recipient: str,
        full_name: str,
        dashboard_url: str,
    ) -> EmailMessage:
        rendered = self.renderer.render(
            template_name="welcome",
            context={
                "full_name": full_name,
                "dashboard_url": dashboard_url,
            },
        )

        return EmailMessage(
            subject=rendered.subject,
            recipients=(recipient,),
            text_body=rendered.text_body,
            html_body=rendered.html_body,
        )

    def project_uploaded_email(
        self,
        *,
        recipient: str,
        full_name: str,
        project_name: str,
        project_url: str,
        framework: str | None = None,
        language: str | None = None,
    ) -> EmailMessage:
        rendered = self.renderer.render(
            template_name="project_uploaded",
            context={
                "full_name": full_name,
                "project_name": project_name,
                "project_url": project_url,
                "framework": framework,
                "language": language,
            },
        )

        return EmailMessage(
            subject=rendered.subject,
            recipients=(recipient,),
            text_body=rendered.text_body,
            html_body=rendered.html_body,
        )

    def scan_completed_email(
        self,
        *,
        recipient: str,
        full_name: str,
        project_name: str,
        report_url: str,
        security_score: int,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        metadata: dict[str, Any] | None = None,
    ) -> EmailMessage:
        rendered = self.renderer.render(
            template_name="scan_completed",
            context={
                "full_name": full_name,
                "project_name": project_name,
                "report_url": report_url,
                "security_score": security_score,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "metadata": metadata or {},
            },
        )

        return EmailMessage(
            subject=rendered.subject,
            recipients=(recipient,),
            text_body=rendered.text_body,
            html_body=rendered.html_body,
        )

    def scan_failed_email(
        self,
        *,
        recipient: str,
        full_name: str,
        project_name: str,
        dashboard_url: str,
    ) -> EmailMessage:
        rendered = self.renderer.render(
            template_name="scan_failed",
            context={
                "full_name": full_name,
                "project_name": project_name,
                "dashboard_url": dashboard_url,
            },
        )
        return EmailMessage(
            subject=rendered.subject,
            recipients=(recipient,),
            text_body=rendered.text_body,
            html_body=rendered.html_body,
        )
