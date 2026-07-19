from app.services.security.remediation.adapters.base import (
    FrameworkAdapter,
    FrameworkContext,
)
from app.services.security.remediation.adapters.fastapi import (
    FastAPIAdapter,
)
from app.services.security.remediation.adapters.registry import (
    FrameworkAdapterRegistry,
)

registry = FrameworkAdapterRegistry(
    [
        FastAPIAdapter(),
    ],
)

__all__ = [
    "FrameworkAdapter",
    "FrameworkAdapterRegistry",
    "FrameworkContext",
    "FastAPIAdapter",
    "registry",
]
