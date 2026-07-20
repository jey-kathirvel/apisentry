from __future__ import annotations

from collections.abc import Iterable

from app.services.security.source_analysis.base import (
    SourceAnalyzer,
)
from app.services.security.source_analysis.context import (
    SourceAnalysisContext,
)
from app.services.security.source_analysis.models import (
    SourceFile,
)


class SourceAnalyzerRegistry:
    def __init__(
        self,
        analyzers: Iterable[
            SourceAnalyzer
        ] | None = None,
    ) -> None:
        self._analyzers: dict[
            str,
            SourceAnalyzer,
        ] = {}

        if analyzers:
            self.register_many(
                analyzers,
            )

    def register(
        self,
        analyzer: SourceAnalyzer,
        *,
        replace: bool = False,
    ) -> SourceAnalyzer:
        name = self._normalize(
            analyzer.name,
        )

        if not name:
            raise ValueError(
                "analyzer name cannot be empty",
            )

        if (
            name in self._analyzers
            and not replace
        ):
            raise ValueError(
                f"source analyzer already registered: {name}",
            )

        self._analyzers[name] = analyzer

        return analyzer

    def register_many(
        self,
        analyzers: Iterable[
            SourceAnalyzer
        ],
        *,
        replace: bool = False,
    ) -> None:
        for analyzer in analyzers:
            self.register(
                analyzer,
                replace=replace,
            )

    def get(
        self,
        name: str,
    ) -> SourceAnalyzer | None:
        return self._analyzers.get(
            self._normalize(
                name,
            ),
        )

    def require(
        self,
        name: str,
    ) -> SourceAnalyzer:
        analyzer = self.get(
            name,
        )

        if analyzer is None:
            raise KeyError(
                f"source analyzer not found: {name}",
            )

        return analyzer

    def contains(
        self,
        name: str,
    ) -> bool:
        return (
            self._normalize(
                name,
            )
            in self._analyzers
        )

    def all(
        self,
    ) -> list[SourceAnalyzer]:
        return sorted(
            self._analyzers.values(),
            key=lambda analyzer: (
                analyzer.priority,
                analyzer.name,
            ),
            reverse=True,
        )

    def resolve(
        self,
        *,
        context: SourceAnalysisContext,
        source_file: SourceFile | None = None,
    ) -> list[SourceAnalyzer]:
        return [
            analyzer
            for analyzer in self.all()
            if analyzer.supports(
                context=context,
                source_file=source_file,
            )
        ]

    def as_dict(
        self,
    ) -> dict[str, dict[str, object]]:
        return {
            name: analyzer.describe()
            for name, analyzer
            in sorted(
                self._analyzers.items(),
            )
        }

    @staticmethod
    def _normalize(
        value: str,
    ) -> str:
        return (
            value
            .strip()
            .lower()
            .replace("_", "-")
            .replace(" ", "-")
        )
