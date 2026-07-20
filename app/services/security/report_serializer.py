from __future__ import annotations

from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

from app.services.security.models import (
    EndpointSecurityAssessment,
    SecurityAnalysisResult,
)


class SecurityReportSerializer:
    """
    Converts security analysis objects into
    deterministic JSON-ready dictionaries.

    This serializer intentionally produces
    stable output ordering so future report
    generation (HTML/PDF/SARIF/API) always
    remains reproducible.
    """

    @classmethod
    def serialize_result(
        cls,
        result: SecurityAnalysisResult,
    ) -> dict[str, Any]:
        return cls._normalize(
            result
        )

    @classmethod
    def serialize_endpoint(
        cls,
        assessment: EndpointSecurityAssessment,
    ) -> dict[str, Any]:
        return cls._normalize(
            assessment
        )

    @classmethod
    def _normalize(
        cls,
        value: Any,
    ) -> Any:

        if value is None:
            return None

        if isinstance(
            value,
            Enum,
        ):
            return value.value

        if is_dataclass(
            value,
        ):
            return cls._normalize(
                asdict(value)
            )

        if isinstance(
            value,
            dict,
        ):
            return {
                str(key): cls._normalize(val)
                for key, val in sorted(
                    value.items(),
                    key=lambda item: str(item[0]),
                )
            }

        if isinstance(
            value,
            (
                list,
                tuple,
                set,
            ),
        ):
            return [
                cls._normalize(item)
                for item in value
            ]

        return value
