from __future__ import annotations

from dataclasses import (
    dataclass,
    field,
)
from datetime import (
    datetime,
    timezone,
)
from typing import Any


@dataclass(
    frozen=True,
    slots=True,
)
class EmailResult:
    success: bool
    provider: str
    attempts: int
    latency_ms: float

    message_id: str | None = None
    error: str | None = None

    delivered_at: datetime | None = None

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    @classmethod
    def delivered(
        cls,
        *,
        provider: str,
        attempts: int,
        latency_ms: float,
        message_id: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> "EmailResult":
        return cls(
            success=True,
            provider=provider,
            attempts=attempts,
            latency_ms=latency_ms,
            message_id=message_id,
            delivered_at=datetime.now(
                timezone.utc,
            ),
            metadata=metadata or {},
        )

    @classmethod
    def failed(
        cls,
        *,
        provider: str,
        attempts: int,
        latency_ms: float,
        error: str,
        metadata: dict[str, Any] | None = None,
    ) -> "EmailResult":
        return cls(
            success=False,
            provider=provider,
            attempts=attempts,
            latency_ms=latency_ms,
            error=error,
            metadata=metadata or {},
        )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return {
            "success": self.success,
            "provider": self.provider,
            "attempts": self.attempts,
            "latency_ms": self.latency_ms,
            "message_id": self.message_id,
            "error": self.error,
            "delivered_at": (
                self.delivered_at.isoformat()
                if self.delivered_at
                else None
            ),
            "metadata": dict(
                self.metadata,
            ),
        }
