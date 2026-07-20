from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlencode

from app.services.mail.delivery_service import EmailDeliveryService
from app.services.mail.result import EmailResult
from app.services.mail.template_service import EmailTemplateService


@dataclass(
    frozen=True,
    slots=True,
)
class AuthEmailWorkflowConfig:
    frontend_url: str = "https://apisentry.ads-ai.in"
    verification_path: str = "/verify-email"
    password_reset_path: str = "/reset-password"
    dashboard_path: str = "/dashboard"

    def __post_init__(self) -> None:
        frontend_url = self.frontend_url.strip().rstrip("/")

        if not frontend_url:
            raise ValueError("Frontend URL is required.")

        if not frontend_url.startswith(("http://", "https://")):
            raise ValueError(
                "Frontend URL must start with http:// or https://."
            )

        for value, field_name in (
            (self.verification_path, "verification_path"),
            (self.password_reset_path, "password_reset_path"),
            (self.dashboard_path, "dashboard_path"),
        ):
            if not value.startswith("/"):
                raise ValueError(
                    f"{field_name} must start with '/'."
                )

        object.__setattr__(
            self,
            "frontend_url",
            frontend_url,
        )

    def verification_url(
        self,
        token: str,
    ) -> str:
        return self._build_url(
            self.verification_path,
            token=token,
        )

    def password_reset_url(
        self,
        token: str,
    ) -> str:
        return self._build_url(
            self.password_reset_path,
            token=token,
        )

    @property
    def dashboard_url(self) -> str:
        return (
            f"{self.frontend_url}"
            f"{self.dashboard_path}"
        )

    def _build_url(
        self,
        path: str,
        **query: str,
    ) -> str:
        return (
            f"{self.frontend_url}"
            f"{path}"
            f"?{urlencode(query)}"
        )


class AuthEmailWorkflow:
    def __init__(
        self,
        *,
        template_service: EmailTemplateService,
        delivery_service: EmailDeliveryService,
        config: AuthEmailWorkflowConfig,
    ) -> None:
        self.template_service = template_service
        self.delivery_service = delivery_service
        self.config = config

    def send_verification_email(
        self,
        *,
        recipient: str,
        full_name: str,
        token: str,
        expires_at: datetime,
    ) -> EmailResult:
        normalized_token = self._validate_token(token)

        message = self.template_service.verification_email(
            recipient=recipient,
            full_name=self._display_name(
                full_name,
                recipient,
            ),
            verification_url=(
                self.config.verification_url(
                    normalized_token,
                )
            ),
            expires_at=expires_at,
        )

        return self.delivery_service.send(message)

    def send_password_reset_email(
        self,
        *,
        recipient: str,
        full_name: str,
        token: str,
        expires_at: datetime,
    ) -> EmailResult:
        normalized_token = self._validate_token(token)

        message = self.template_service.password_reset_email(
            recipient=recipient,
            full_name=self._display_name(
                full_name,
                recipient,
            ),
            reset_url=(
                self.config.password_reset_url(
                    normalized_token,
                )
            ),
            expires_at=expires_at,
        )

        return self.delivery_service.send(message)

    def send_welcome_email(
        self,
        *,
        recipient: str,
        full_name: str,
    ) -> EmailResult:
        message = self.template_service.welcome_email(
            recipient=recipient,
            full_name=self._display_name(
                full_name,
                recipient,
            ),
            dashboard_url=self.config.dashboard_url,
        )

        return self.delivery_service.send(message)

    @staticmethod
    def _validate_token(
        token: str,
    ) -> str:
        normalized = token.strip()

        if not normalized:
            raise ValueError(
                "Email workflow token is required."
            )

        return normalized

    @staticmethod
    def _display_name(
        full_name: str,
        email: str,
    ) -> str:
        normalized_name = full_name.strip()

        if normalized_name:
            return normalized_name

        local_part = email.split("@", 1)[0].strip()

        return local_part or "API Sentry User"
