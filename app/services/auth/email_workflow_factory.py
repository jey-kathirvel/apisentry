from __future__ import annotations

import os
from pathlib import Path

from app.core.email_config import EmailConfig
from app.services.auth.email_workflow import (
    AuthEmailWorkflow,
    AuthEmailWorkflowConfig,
)
from app.services.mail.delivery_service import EmailDeliveryService
from app.services.mail.provider_factory import create_email_provider
from app.services.mail.template_renderer import EmailTemplateRenderer
from app.services.mail.template_service import EmailTemplateService


def create_auth_email_workflow(
    *,
    email_config: EmailConfig | None = None,
    template_directory: str | Path = (
        "app/templates/emails"
    ),
    raise_on_delivery_failure: bool = True,
) -> AuthEmailWorkflow:
    resolved_email_config = (
        email_config
        or EmailConfig.from_environment()
    )

    resolved_email_config.validate()

    frontend_url = os.getenv(
        "FRONTEND_URL",
        "https://apisentry.ads-ai.in",
    ).strip()

    app_name = os.getenv(
        "APP_NAME",
        "API Sentry",
    ).strip()

    support_email = os.getenv(
        "SUPPORT_EMAIL",
        resolved_email_config.default_sender_email,
    ).strip()

    renderer = EmailTemplateRenderer(
        template_directory=template_directory,
        app_name=app_name,
        app_url=frontend_url,
        support_email=support_email,
        logo_url=(
            os.getenv("EMAIL_LOGO_URL")
            or None
        ),
    )

    template_service = EmailTemplateService(
        renderer,
    )

    provider = create_email_provider(
        resolved_email_config,
    )

    delivery_service = EmailDeliveryService(
        provider,
        raise_on_failure=(
            raise_on_delivery_failure
        ),
    )

    workflow_config = AuthEmailWorkflowConfig(
        frontend_url=frontend_url,
        verification_path=os.getenv(
            "EMAIL_VERIFICATION_PATH",
            "/verify-email",
        ),
        password_reset_path=os.getenv(
            "PASSWORD_RESET_PATH",
            "/reset-password",
        ),
        dashboard_path=os.getenv(
            "DASHBOARD_PATH",
            "/dashboard",
        ),
    )

    return AuthEmailWorkflow(
        template_service=template_service,
        delivery_service=delivery_service,
        config=workflow_config,
    )
