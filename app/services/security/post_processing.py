from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from enum import Enum
from typing import Any

from app.services.security.models import (
    SecurityAnalysisResult,
    SecurityFinding,
)


class SecurityFindingProcessor:
    """
    Normalizes analyzer output before scoring and presentation.

    Responsibilities:
    - Remove duplicate findings.
    - Apply deterministic severity-first ordering.
    - Add project-level finding and severity summaries.
    """

    _SEVERITY_ORDER: dict[str, int] = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    @classmethod
    def normalize_findings(
        cls,
        findings: Iterable[SecurityFinding],
    ) -> list[SecurityFinding]:
        unique_findings: dict[
            tuple[Any, ...],
            SecurityFinding,
        ] = {}

        for finding in findings:
            key = cls._deduplication_key(
                finding
            )

            if key not in unique_findings:
                unique_findings[key] = finding

        return sorted(
            unique_findings.values(),
            key=cls._sorting_key,
        )

    @classmethod
    def enrich_result(
        cls,
        result: SecurityAnalysisResult,
    ) -> SecurityAnalysisResult:
        severity_counts: Counter[str] = Counter()

        rule_counts: Counter[str] = Counter()

        endpoint_finding_counts: dict[
            str,
            int,
        ] = {}

        total_findings = 0

        for assessment in result.assessments:
            normalized_findings = (
                cls.normalize_findings(
                    assessment.findings
                )
            )

            assessment.findings = (
                normalized_findings
            )

            finding_count = len(
                normalized_findings
            )

            total_findings += finding_count

            endpoint_key = (
                f"{assessment.method} "
                f"{assessment.path}"
            )

            endpoint_finding_counts[
                endpoint_key
            ] = finding_count

            for finding in normalized_findings:
                severity = cls._enum_value(
                    getattr(
                        finding,
                        "severity",
                        "info",
                    )
                ).lower()

                severity_counts[
                    severity
                ] += 1

                rule_id = cls._rule_identifier(
                    finding
                )

                if rule_id:
                    rule_counts[
                        rule_id
                    ] += 1

        severity_summary = {
            severity: severity_counts.get(
                severity,
                0,
            )
            for severity in (
                "critical",
                "high",
                "medium",
                "low",
                "info",
            )
        }

        result.metadata.update(
            {
                "finding_count": (
                    total_findings
                ),
                "severity_summary": (
                    severity_summary
                ),
                "rule_summary": dict(
                    sorted(
                        rule_counts.items()
                    )
                ),
                "endpoint_finding_counts": (
                    dict(
                        sorted(
                            endpoint_finding_counts
                            .items()
                        )
                    )
                ),
                "affected_endpoint_count": (
                    sum(
                        1
                        for count
                        in endpoint_finding_counts
                        .values()
                        if count > 0
                    )
                ),
                "clean_endpoint_count": (
                    sum(
                        1
                        for count
                        in endpoint_finding_counts
                        .values()
                        if count == 0
                    )
                ),
            }
        )

        return result

    @classmethod
    def _deduplication_key(
        cls,
        finding: SecurityFinding,
    ) -> tuple[Any, ...]:
        return (
            cls._rule_identifier(
                finding
            ),
            cls._enum_value(
                getattr(
                    finding,
                    "severity",
                    "",
                )
            ).lower(),
            cls._normalized_text(
                getattr(
                    finding,
                    "title",
                    "",
                )
            ),
            cls._normalized_text(
                getattr(
                    finding,
                    "description",
                    "",
                )
            ),
            cls._normalized_text(
                getattr(
                    finding,
                    "recommendation",
                    "",
                )
            ),
            cls._normalized_text(
                getattr(
                    finding,
                    "parameter_name",
                    "",
                )
            ),
            cls._normalized_text(
                getattr(
                    finding,
                    "file_path",
                    "",
                )
            ),
            cls._normalized_value(
                getattr(
                    finding,
                    "line_number",
                    None,
                )
            ),
        )

    @classmethod
    def _sorting_key(
        cls,
        finding: SecurityFinding,
    ) -> tuple[Any, ...]:
        severity = cls._enum_value(
            getattr(
                finding,
                "severity",
                "info",
            )
        ).lower()

        return (
            cls._SEVERITY_ORDER.get(
                severity,
                99,
            ),
            cls._rule_identifier(
                finding
            ),
            cls._normalized_text(
                getattr(
                    finding,
                    "title",
                    "",
                )
            ),
            cls._normalized_text(
                getattr(
                    finding,
                    "parameter_name",
                    "",
                )
            ),
            cls._normalized_value(
                getattr(
                    finding,
                    "line_number",
                    None,
                )
            ),
        )

    @classmethod
    def _rule_identifier(
        cls,
        finding: SecurityFinding,
    ) -> str:
        for attribute_name in (
            "rule_id",
            "code",
            "finding_id",
            "identifier",
        ):
            value = getattr(
                finding,
                attribute_name,
                None,
            )

            if value not in (
                None,
                "",
            ):
                return str(
                    value
                ).strip().upper()

        return ""

    @staticmethod
    def _enum_value(
        value: Any,
    ) -> str:
        if isinstance(
            value,
            Enum,
        ):
            return str(
                value.value
            )

        return str(
            value or ""
        )

    @staticmethod
    def _normalized_text(
        value: Any,
    ) -> str:
        return " ".join(
            str(
                value or ""
            ).split()
        ).casefold()

    @staticmethod
    def _normalized_value(
        value: Any,
    ) -> Any:
        if isinstance(
            value,
            Enum,
        ):
            return value.value

        if isinstance(
            value,
            dict,
        ):
            return tuple(
                sorted(
                    (
                        str(key),
                        SecurityFindingProcessor
                        ._normalized_value(
                            item_value
                        ),
                    )
                    for key, item_value
                    in value.items()
                )
            )

        if isinstance(
            value,
            (
                list,
                tuple,
                set,
            ),
        ):
            return tuple(
                SecurityFindingProcessor
                ._normalized_value(
                    item
                )
                for item in value
            )

        return value
