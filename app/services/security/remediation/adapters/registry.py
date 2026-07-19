from __future__ import annotations

from collections.abc import Iterable

from app.services.security.remediation.adapters.base import (
    FrameworkAdapter,
)
from app.services.security.remediation.adapters.base import (
    FrameworkContext,
)


class FrameworkAdapterRegistry:
    """
    Registry and resolver for framework-specific
    remediation adapters.
    """

    def __init__(
        self,
        adapters: Iterable[
            FrameworkAdapter
        ]
        | None = None,
    ) -> None:
        self._adapters: dict[
            str,
            FrameworkAdapter,
        ] = {}

        if adapters is not None:
            self.register_many(
                adapters,
            )

    def register(
        self,
        adapter: FrameworkAdapter,
        *,
        replace: bool = False,
    ) -> None:
        name = adapter.normalized_name

        if not name:
            raise ValueError(
                "Framework adapter name "
                "cannot be empty."
            )

        if (
            name in self._adapters
            and not replace
        ):
            raise ValueError(
                "Framework adapter already "
                f"registered: {adapter.name}"
            )

        self._adapters[name] = adapter

    def register_many(
        self,
        adapters: Iterable[
            FrameworkAdapter
        ],
        *,
        replace: bool = False,
    ) -> None:
        for adapter in adapters:
            self.register(
                adapter,
                replace=replace,
            )

    def get(
        self,
        name: str,
    ) -> FrameworkAdapter | None:
        normalized = (
            FrameworkContext.normalize_name(
                name,
            )
        )

        direct = self._adapters.get(
            normalized,
        )

        if direct is not None:
            return direct

        for adapter in self.all():
            if normalized in (
                adapter.normalized_aliases
            ):
                return adapter

        return None

    def require(
        self,
        name: str,
    ) -> FrameworkAdapter:
        adapter = self.get(
            name,
        )

        if adapter is None:
            raise KeyError(
                "No framework adapter "
                f"registered for: {name}"
            )

        return adapter

    def resolve(
        self,
        context: FrameworkContext,
    ) -> FrameworkAdapter | None:
        supported = [
            adapter
            for adapter in self.all()
            if adapter.supports(
                context,
            )
        ]

        if not supported:
            return None

        return min(
            supported,
            key=lambda adapter: (
                adapter.priority,
                adapter.normalized_name,
            ),
        )

    def resolve_all(
        self,
        context: FrameworkContext,
    ) -> list[
        FrameworkAdapter
    ]:
        return sorted(
            (
                adapter
                for adapter in self.all()
                if adapter.supports(
                    context,
                )
            ),
            key=lambda adapter: (
                adapter.priority,
                adapter.normalized_name,
            ),
        )

    def contains(
        self,
        name: str,
    ) -> bool:
        return self.get(
            name,
        ) is not None

    def all(
        self,
    ) -> list[
        FrameworkAdapter
    ]:
        return sorted(
            self._adapters.values(),
            key=lambda adapter: (
                adapter.priority,
                adapter.normalized_name,
            ),
        )

    def as_dict(
        self,
    ) -> dict[str, dict]:
        return {
            adapter.name: (
                adapter.describe()
            )
            for adapter in self.all()
        }

    def __len__(
        self,
    ) -> int:
        return len(
            self._adapters
        )

    def __contains__(
        self,
        name: object,
    ) -> bool:
        if not isinstance(
            name,
            str,
        ):
            return False

        return self.contains(
            name,
        )
