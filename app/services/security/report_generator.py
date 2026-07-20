from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services.security.models import (
    SecurityAnalysisResult,
)
from app.services.security.report_serializer import (
    SecurityReportSerializer,
)


class SecurityReportGenerator:
    """
    Generates a canonical report structure that can
    be consumed by HTML, PDF, JSON, SARIF and API
    responses.
    """

    REPORT_VERSION = "1.0"

    @classmethod
    def generate(
        cls,
        result: SecurityAnalysisResult,
    ) -> dict[str, Any]:

        serialized = (
            SecurityReportSerializer
            .serialize_result(result)
        )

        return {
            "report_version": cls.REPORT_VERSION,
            "generated_at": datetime.now(
                UTC
            ).isoformat(),
            "summary": {
                "score": serialized.get(
                    "score"
                ),
                "severity": serialized.get(
                    "severity"
                ),
                "metadata": serialized.get(
                    "metadata",
                    {},
                ),
            },
            "assessments": serialized.get(
                "assessments",
                [],
            ),
        }
