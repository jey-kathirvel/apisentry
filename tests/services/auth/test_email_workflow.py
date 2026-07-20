from __future__ import annotations

from datetime import (
    datetime,
    timezone,
)
from pathlib import Path

import pytest

from app.services.auth.email_workflow import (
    AuthEmailWorkflow,
    AuthEmailWorkflowConfig,
)
from app.services.mail.base import EmailProvider
from app.services.mail.delivery_service import EmailDeliveryService
from app.services.mail.message import EmailMessage
from app.services.mail.result import EmailResult
from app.services.mail.template_renderer import EmailTemplateRenderer
from app.services.mail.template_service import EmailTemplateService


TEMPLATE_DIRECTORY = (
    Path(__file__)
    .resolve()
    .parents[3]
    / "app"
    / "templates"
    / "emails"
)


class CapturingProvider(EmailProvider):
    provider_name = "capture"

    def __init__(self) -> None:
        self.messages: list[EmailMessage] = []

    def send(
        self,
        message: EmailMessage,
    ) -> EmailResult:
        self.messages.append(message)

        return EmailResult.delivered(
            provider=self.provider_name,
            attempts=1,
            latency_ms=1.0,
            message_id=f"message-{len(self.messages)}",
        )


@pytest.fixture()
def provider() -> CapturingProvider:
    return CapturingProvider()


@pytest.fixture()
def workflow(
    provider: CapturingProvider,
) -> AuthEmailWorkflow:
    renderer = EmailTemplateRenderer(
        template_directory=TEMPLATE_DIRECTORY,
        app_name="API Sentry",
        app_url="https://apisentry.ads-ai.in",
        support_email="support@ads-ai.in",
    )

    return AuthEmailWorkflow(
        template_service=EmailTemplateService(
            renderer,
        ),
        delivery_service=EmailDeliveryService(
            provider,
        ),
        config=AuthEmailWorkflowConfig(
            frontend_url=(
                "https://apisentry.ads-ai.in"
            ),
        ),
    )


def test_verification_url_encodes_token() -> None:
    config = AuthEmailWorkflowConfig(
        frontend_url="https://example.com/",
    )

    url = config.verification_url(
        "token with + symbols",
    )

    assert url == (
        "https://example.com/verify-email"
        "?token=token+with+%2B+symbols"
    )


def test_invalid_frontend_url_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="must start",
    ):
        AuthEmailWorkflowConfig(
            frontend_url="apisentry.example.com",
        )


def test_sends_verification_email(
    workflow: AuthEmailWorkflow,
    provider: CapturingProvider,
) -> None:
    expires_at = datetime(
        2026,
        7,
        20,
        10,
        30,
        tzinfo=timezone.utc,
    )

    result = workflow.send_verification_email(
        recipient="jey@example.com",
        full_name="Jey Kathirvel",
        token="verification-token",
        expires_at=expires_at,
    )

    assert result.success is True
    assert len(provider.messages) == 1

    message = provider.messages[0]

    assert message.subject == (
        "Verify your API Sentry email address"
    )
    assert message.recipients == (
        "jey@example.com",
    )
    assert (
        "token=verification-token"
        in (message.html_body or "")
    )


def test_sends_password_reset_email(
    workflow: AuthEmailWorkflow,
    provider: CapturingProvider,
) -> None:
    expires_at = datetime(
        2026,
        7,
        20,
        10,
        30,
        tzinfo=timezone.utc,
    )

    result = workflow.send_password_reset_email(
        recipient="jey@example.com",
        full_name="Jey Kathirvel",
        token="reset-token",
        expires_at=expires_at,
    )

    assert result.success is True

    message = provider.messages[0]

    assert message.subject == (
        "Reset your API Sentry password"
    )
    assert (
        "token=reset-token"
        in (message.text_body or "")
    )


def test_sends_welcome_email(
    workflow: AuthEmailWorkflow,
    provider: CapturingProvider,
) -> None:
    result = workflow.send_welcome_email(
        recipient="jey@example.com",
        full_name="Jey Kathirvel",
    )

    assert result.success is True

    message = provider.messages[0]

    assert message.subject == (
        "Welcome to API Sentry"
    )
    assert (
        "https://apisentry.ads-ai.in/dashboard"
        in (message.html_body or "")
    )


def test_empty_name_uses_email_local_part(
    workflow: AuthEmailWorkflow,
    provider: CapturingProvider,
) -> None:
    workflow.send_welcome_email(
        recipient="jey.kathirvel@example.com",
        full_name="",
    )

    message = provider.messages[0]

    assert (
        "Hello jey.kathirvel"
        in (message.text_body or "")
    )


def test_empty_token_rejected(
    workflow: AuthEmailWorkflow,
    provider: CapturingProvider,
) -> None:
    with pytest.raises(
        ValueError,
        match="token is required",
    ):
        workflow.send_verification_email(
            recipient="jey@example.com",
            full_name="Jey",
            token=" ",
            expires_at=datetime.now(
                timezone.utc,
            ),
        )

    assert provider.messages == []


def test_sends_project_and_scan_lifecycle_emails(
    workflow: AuthEmailWorkflow,
    provider: CapturingProvider,
) -> None:
    workflow.send_project_uploaded_email(
        recipient="jey@example.com",
        full_name="Jey Kathirvel",
        project_name="Payments API",
        project_url="https://apisentry.ads-ai.in/dashboard?project_id=12",
        framework="FastAPI",
        language="Python",
    )
    workflow.send_scan_completed_email(
        recipient="jey@example.com",
        full_name="Jey Kathirvel",
        project_name="Payments API",
        report_url="https://apisentry.ads-ai.in/dashboard?report_project_id=12",
        security_score=82,
        severity_counts={"critical": 1, "high": 2, "medium": 3, "low": 4},
    )
    workflow.send_scan_failed_email(
        recipient="jey@example.com",
        full_name="Jey Kathirvel",
        project_name="Payments API",
        dashboard_url="https://apisentry.ads-ai.in/dashboard",
    )

    assert len(provider.messages) == 3
    assert "Payments API" in (provider.messages[0].text_body or "")
    assert "Security score: 82" in (provider.messages[1].text_body or "")
    assert "stopped before completion" in (provider.messages[2].text_body or "")
