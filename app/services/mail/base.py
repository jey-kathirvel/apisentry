from __future__ import annotations

from abc import (
    ABC,
    abstractmethod,
)

from app.services.mail.message import (
    EmailMessage,
)
from app.services.mail.result import (
    EmailResult,
)


class EmailProvider(
    ABC,
):
    provider_name: str

    @abstractmethod
    def send(
        self,
        message: EmailMessage,
    ) -> EmailResult:
        raise NotImplementedError
