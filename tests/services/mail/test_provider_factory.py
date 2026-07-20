from __future__ import annotations

import pytest

from app.core.email_config import (
    EmailConfig,
)
from app.services.mail.exceptions import (
    UnsupportedEmailProviderError,
)
from app.services.mail.provider_factory import (
    create_email_provider,
)
from app.services.mail.smtp_provider import (
    SMTPEmailProvider,
)


def test_factory_creates_smtp_provider() -> None:
    provider = create_email_provider(
        EmailConfig(
            provider="smtp",
        )
    )

    assert isinstance(
        provider,
        SMTPEmailProvider,
    )


def test_factory_rejects_unknown_provider() -> None:
    with pytest.raises(
        UnsupportedEmailProviderError,
        match="Unsupported email provider",
    ):
        create_email_provider(
            EmailConfig(
                provider="unknown",
            )
        )
