from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from jinja2 import (
    Environment,
    FileSystemLoader,
    StrictUndefined,
    TemplateNotFound,
    select_autoescape,
)

from app.services.mail.exceptions import (
    EmailConfigurationError,
    EmailValidationError,
)


@dataclass(
    frozen=True,
    slots=True,
)
class RenderedEmail:
    subject: str
    html_body: str
    text_body: str


class EmailTemplateRenderer:
    def __init__(
        self,
        *,
        template_directory: str | Path = "app/templates/emails",
        app_name: str = "API Sentry",
        app_url: str = "https://apisentry.ads-ai.in",
        support_email: str = "support@ads-ai.in",
        logo_url: str | None = None,
    ) -> None:
        self.template_directory = Path(
            template_directory,
        ).resolve()

        if not self.template_directory.exists():
            raise EmailConfigurationError(
                "Email template directory does not exist: "
                f"{self.template_directory}"
            )

        if not self.template_directory.is_dir():
            raise EmailConfigurationError(
                "Email template path is not a directory: "
                f"{self.template_directory}"
            )

        self.app_name = app_name.strip()
        self.app_url = app_url.strip().rstrip("/")
        self.support_email = support_email.strip()

        self.logo_url = (
            logo_url
            or (
                f"{self.app_url}/static/"
                "images/api-sentry-logo.png"
            )
        )

        self.environment = Environment(
            loader=FileSystemLoader(
                str(self.template_directory),
            ),
            autoescape=select_autoescape(
                enabled_extensions=(
                    "html",
                    "xml",
                ),
                default_for_string=True,
                default=True,
            ),
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
        )

        self.environment.globals.update(
            app_name=self.app_name,
            app_url=self.app_url,
            support_email=self.support_email,
            logo_url=self.logo_url,
        )

    def render(
        self,
        *,
        template_name: str,
        context: Mapping[str, Any],
    ) -> RenderedEmail:
        normalized_name = (
            template_name.strip()
            .removesuffix(".subject.txt")
            .removesuffix(".html")
            .removesuffix(".txt")
        )

        if not normalized_name:
            raise EmailValidationError(
                "Email template name is required."
            )

        try:
            subject_template = self.environment.get_template(
                f"{normalized_name}.subject.txt"
            )

            html_template = self.environment.get_template(
                f"{normalized_name}.html"
            )

            text_template = self.environment.get_template(
                f"{normalized_name}.txt"
            )

        except TemplateNotFound as exc:
            raise EmailConfigurationError(
                "Email template file was not found: "
                f"{exc.name}"
            ) from exc

        template_context = dict(context)

        subject = subject_template.render(
            **template_context,
        ).strip()

        html_body = html_template.render(
            **template_context,
        ).strip()

        text_body = text_template.render(
            **template_context,
        ).strip()

        if not subject:
            raise EmailValidationError(
                "Rendered email subject is empty."
            )

        if not html_body:
            raise EmailValidationError(
                "Rendered HTML email body is empty."
            )

        if not text_body:
            raise EmailValidationError(
                "Rendered text email body is empty."
            )

        return RenderedEmail(
            subject=subject,
            html_body=html_body,
            text_body=text_body,
        )
