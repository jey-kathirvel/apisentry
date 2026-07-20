from app.core.email_config import (
    EmailConfig,
)
from app.services.mail.base import (
    EmailProvider,
)
from app.services.mail.delivery_service import (
    EmailDeliveryService,
)
from app.services.mail.exceptions import (
    EmailConfigurationError,
    EmailDeliveryError,
    EmailError,
    EmailProviderError,
    EmailValidationError,
    UnsupportedEmailProviderError,
)
from app.services.mail.message import (
    EmailAttachment,
    EmailMessage,
)
from app.services.mail.provider_factory import (
    create_email_provider,
)
from app.services.mail.result import (
    EmailResult,
)
from app.services.mail.smtp_provider import (
    SMTPEmailProvider,
)

__all__ = [
    "EmailAttachment",
    "EmailConfig",
    "EmailConfigurationError",
    "EmailDeliveryError",
    "EmailDeliveryService",
    "EmailError",
    "EmailMessage",
    "EmailProvider",
    "EmailProviderError",
    "EmailResult",
    "EmailValidationError",
    "SMTPEmailProvider",
    "UnsupportedEmailProviderError",
    "create_email_provider",
    "EmailTemplateRenderer",
    "EmailTemplateService",
    "RenderedEmail",
]

from app.services.mail.template_renderer import (
    EmailTemplateRenderer,
    RenderedEmail,
)

from app.services.mail.template_service import (
    EmailTemplateService,
)
