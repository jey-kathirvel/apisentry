from __future__ import annotations

from copy import deepcopy

from app.services.security.models import SecurityFinding
from app.services.security.remediation.adapters import (
    FrameworkAdapter,
    FrameworkAdapterRegistry,
    FrameworkContext,
)
from app.services.security.remediation.adapters import (
    registry as default_adapter_registry,
)
from app.services.security.remediation.merger import (
    RemediationMerger,
)
from app.services.security.remediation.models import (
    RemediationGuidance,
)


class FrameworkRemediationService:
    """
    Applies the highest-priority compatible framework adapter to
    generic remediation guidance.

    The original finding and remediation guidance are never mutated.
    """

    def __init__(
        self,
        *,
        adapter_registry: FrameworkAdapterRegistry | None = None,
        merger: type[RemediationMerger] = RemediationMerger,
    ) -> None:
        self.adapter_registry = (
            adapter_registry
            or default_adapter_registry
        )
        self.merger = merger

    def enrich(
        self,
        *,
        finding: SecurityFinding,
        guidance: RemediationGuidance,
        context: FrameworkContext,
    ) -> RemediationGuidance:
        adapter = self.resolve_adapter(
            context=context,
        )

        if adapter is None:
            return deepcopy(
                guidance,
            )

        patch = adapter.decorate(
            finding=finding,
            guidance=guidance,
            context=context,
        )

        enriched = self.merger.merge(
            guidance,
            patch,
        )

        enriched.metadata = {
            **enriched.metadata,
            "framework_remediation": {
                "applied": True,
                "adapter": adapter.name,
                "framework": context.framework,
                "language": context.language,
                "endpoint": context.endpoint_identifier,
            },
        }

        return enriched

    def resolve_adapter(
        self,
        *,
        context: FrameworkContext,
    ) -> FrameworkAdapter | None:
        compatible: list[FrameworkAdapter] = []

        for adapter in self.adapter_registry.all():
            if adapter.supports(
                context,
            ):
                compatible.append(
                    adapter,
                )

        if not compatible:
            return None

        compatible.sort(
            key=lambda adapter: adapter.priority,
            reverse=True,
        )

        return compatible[0]
