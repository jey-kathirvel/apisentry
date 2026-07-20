from __future__ import annotations

from app.core.email_config import (
    EmailConfig,
)
from app.services.mail.base import (
    EmailProvider,
)
from app.services.mail.exceptions import (
    UnsupportedEmailProviderError,
)
from app.services.mail.smtp_provider import (
    SMTPEmailProvider,
)


def create_email_provider(
    config: EmailConfig,
) -> EmailProvider:
    provider_name = (
        config.provider.strip().lower()
    )

    if provider_name == "smtp":
        return SMTPEmailProvider(
            config,
        )

    raise UnsupportedEmailProviderError(
        (
            "Unsupported email provider: "
            f"{provider_name}"
        )
    )
