from __future__ import annotations

from abc import ABC
from abc import abstractmethod

from app.services.security.source_analysis.context import (
    SourceAnalysisContext,
)
from app.services.security.source_analysis.models import (
    SourceAnalysisResult,
    SourceFile,
)


class SourceAnalyzer(
    ABC,
):
    name: str = "source-analyzer"
    languages: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()
    priority: int = 0

    def supports(
        self,
        *,
        context: SourceAnalysisContext,
        source_file: SourceFile | None = None,
    ) -> bool:
        language = (
            source_file.language
            if source_file is not None
            else context.normalized_language
        ).strip().lower()

        framework = (
            context.normalized_framework
        )

        language_supported = (
            not self.languages
            or not language
            or language
            in {
                item.strip().lower()
                for item in self.languages
            }
        )

        framework_supported = (
            not self.frameworks
            or framework
            in {
                item.strip().lower()
                for item in self.frameworks
            }
        )

        return (
            language_supported
            and framework_supported
        )

    @abstractmethod
    def analyze(
        self,
        *,
        files: list[SourceFile],
        context: SourceAnalysisContext,
    ) -> SourceAnalysisResult:
        raise NotImplementedError

    def describe(
        self,
    ) -> dict[str, object]:
        return {
            "name": self.name,
            "languages": list(
                self.languages,
            ),
            "frameworks": list(
                self.frameworks,
            ),
            "priority": self.priority,
        }
