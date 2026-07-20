from __future__ import annotations

from typing import Any

from app.services.security.models import (
    SecurityAnalysisResult,
)


class ExecutiveSummaryGenerator:
    """
    Generates a concise executive summary suitable
    for dashboards, HTML reports and PDF exports.
    """

    @classmethod
    def generate(
        cls,
        result: SecurityAnalysisResult,
    ) -> dict[str, Any]:

        metadata = result.metadata or {}

        severity_summary = metadata.get(
            "severity_summary",
            {},
        )

        rule_summary = metadata.get(
            "rule_summary",
            {},
        )

        sorted_rules = sorted(
            rule_summary.items(),
            key=lambda item: (
                -item[1],
                item[0],
            ),
        )

        return {
            "overall_score": result.score,
            "overall_severity": str(
                result.severity.value
            ),
            "risk_grade": cls._risk_grade(
                result.score,
            ),
            "endpoint_count": metadata.get(
                "endpoint_count",
                0,
            ),
            "affected_endpoint_count": metadata.get(
                "affected_endpoint_count",
                0,
            ),
            "clean_endpoint_count": metadata.get(
                "clean_endpoint_count",
                0,
            ),
            "finding_count": metadata.get(
                "finding_count",
                0,
            ),
            "severity_summary": severity_summary,
            "top_rules": [
                {
                    "rule": rule,
                    "count": count,
                }
                for rule, count
                in sorted_rules[:10]
            ],
        }

    @staticmethod
    def _risk_grade(
        score: int,
    ) -> str:

        if score >= 95:
            return "A+"

        if score >= 90:
            return "A"

        if score >= 80:
            return "B"

        if score >= 70:
            return "C"

        if score >= 60:
            return "D"

        if score >= 40:
            return "E"

        return "F"
