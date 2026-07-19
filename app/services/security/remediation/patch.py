from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from typing import Any

from app.services.security.remediation.models import (
    SecureCodeExample,
)


@dataclass(slots=True)
class RemediationPatch:
    implementation_steps: list[str] = field(
        default_factory=list,
    )

    validation_steps: list[str] = field(
        default_factory=list,
    )

    code_examples: list[
        SecureCodeExample
    ] = field(
        default_factory=list,
    )

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )
