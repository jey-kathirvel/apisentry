from __future__ import annotations

from collections import Counter
from copy import deepcopy
from typing import Any

from app.services.security.source_analysis.base import (
    SourceAnalyzer,
)
from app.services.security.source_analysis.context import (
    SourceAnalysisContext,
)
from app.services.security.source_analysis.loader import (
    SourceFileLoader,
)
from app.services.security.source_analysis.models import (
    SourceAnalysisResult,
    SourceFile,
    SourceIssue,
)
from app.services.security.source_analysis.registry import (
    SourceAnalyzerRegistry,
)


class SourceAnalysisService:
    def __init__(
        self,
        *,
        analyzer_registry: SourceAnalyzerRegistry,
        loader: SourceFileLoader | None = None,
    ) -> None:
        self.analyzer_registry = analyzer_registry
        self.loader = loader or SourceFileLoader()

    def analyze(
        self,
        *,
        context: SourceAnalysisContext,
    ) -> SourceAnalysisResult:
        files, skipped_files, loader_errors = (
            self.loader.discover(
                context=context,
            )
        )

        analyzers = self.analyzer_registry.resolve(
            context=context,
        )

        combined_issues: list[SourceIssue] = []
        errors: list[str] = list(
            loader_errors,
        )
        analyzer_results: list[
            dict[str, Any]
        ] = []

        for analyzer in analyzers:
            supported_files = self._supported_files(
                analyzer=analyzer,
                files=files,
                context=context,
            )

            try:
                result = analyzer.analyze(
                    files=supported_files,
                    context=context,
                )
            except Exception as exc:
                errors.append(
                    f"{analyzer.name}: "
                    f"{type(exc).__name__}: {exc}",
                )

                analyzer_results.append(
                    {
                        "analyzer": analyzer.name,
                        "files_scanned": 0,
                        "issue_count": 0,
                        "successful": False,
                        "error": str(
                            exc,
                        ),
                    },
                )
                continue

            result.deduplicate()

            combined_issues.extend(
                deepcopy(
                    result.issues,
                ),
            )

            errors.extend(
                f"{analyzer.name}: {error}"
                for error in result.errors
            )

            analyzer_results.append(
                {
                    "analyzer": result.analyzer,
                    "files_scanned": (
                        result.files_scanned
                    ),
                    "issue_count": (
                        result.issue_count
                    ),
                    "successful": (
                        result.successful
                    ),
                    "metadata": deepcopy(
                        result.metadata,
                    ),
                },
            )

        aggregate = SourceAnalysisResult(
            analyzer="source-analysis-service",
            files_scanned=len(
                files,
            ),
            issues=combined_issues,
            skipped_files=skipped_files,
            errors=errors,
            metadata={
                "project_root": str(
                    context.project_root,
                ),
                "project_id": context.project_id,
                "project_name": (
                    context.project_name
                ),
                "framework": context.framework,
                "language": context.language,
                "analyzer_count": len(
                    analyzers,
                ),
                "analyzers": analyzer_results,
                "discovered_files": [
                    source_file.to_dict()
                    for source_file in files
                ],
            },
        )

        aggregate.deduplicate()

        aggregate.metadata[
            "summary"
        ] = self._build_summary(
            result=aggregate,
        )

        return aggregate

    @staticmethod
    def _supported_files(
        *,
        analyzer: SourceAnalyzer,
        files: list[SourceFile],
        context: SourceAnalysisContext,
    ) -> list[SourceFile]:
        return [
            source_file
            for source_file in files
            if analyzer.supports(
                context=context,
                source_file=source_file,
            )
        ]

    @staticmethod
    def _build_summary(
        *,
        result: SourceAnalysisResult,
    ) -> dict[str, Any]:
        severity_counts = Counter(
            issue.severity.value
            for issue in result.issues
        )

        confidence_counts = Counter(
            issue.confidence.value
            for issue in result.issues
        )

        category_counts = Counter(
            issue.category
            for issue in result.issues
        )

        rule_counts = Counter(
            issue.rule_id
            for issue in result.issues
        )

        return {
            "issue_count": result.issue_count,
            "files_scanned": (
                result.files_scanned
            ),
            "skipped_file_count": len(
                result.skipped_files,
            ),
            "error_count": len(
                result.errors,
            ),
            "severity": dict(
                sorted(
                    severity_counts.items(),
                ),
            ),
            "confidence": dict(
                sorted(
                    confidence_counts.items(),
                ),
            ),
            "categories": dict(
                sorted(
                    category_counts.items(),
                ),
            ),
            "rules": dict(
                sorted(
                    rule_counts.items(),
                ),
            ),
        }
