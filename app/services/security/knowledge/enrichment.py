from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.services.security.knowledge.default_rules import (
    registry,
)
from app.services.security.models import (
    SecurityFinding,
)


class SecurityKnowledgeEnricher:
    """
    Enriches findings with security intelligence
    from the central knowledge registry.

    The original finding is not modified.
    """

    @classmethod
    def enrich(
        cls,
        finding: SecurityFinding,
    ) -> SecurityFinding:
        enriched = deepcopy(
            finding
        )

        rule_id = cls._normalize_rule_id(
            enriched.rule_id
        )

        if not rule_id:
            return enriched

        record = registry.get(
            rule_id
        )

        if record is None:
            return enriched

        if not enriched.title.strip():
            enriched.title = record.title

        if not enriched.description.strip():
            enriched.description = (
                record.description
            )

        if not enriched.remediation.strip():
            enriched.remediation = (
                record.remediation
            )

        if (
            not enriched.owasp_reference
            and record.owasp_api_categories
        ):
            enriched.owasp_reference = (
                record.owasp_api_categories[0]
            )

        if (
            not enriched.cwe_id
            and record.cwe_ids
        ):
            enriched.cwe_id = (
                record.cwe_ids[0]
            )

        knowledge_metadata = {
            "rule_id": record.rule_id,
            "category": record.category,
            "owasp_api_categories": list(
                record.owasp_api_categories
            ),
            "cwe_ids": list(
                record.cwe_ids
            ),
            "capec_ids": list(
                record.capec_ids
            ),
            "references": list(
                record.references
            ),
            "cvss_vector": record.cvss_vector,
            "cvss_score": record.cvss_score,
            "compliance": {
                framework: list(
                    controls
                )
                for framework, controls
                in record.compliance.items()
            },
        }

        existing_knowledge = (
            enriched.metadata.get(
                "knowledge",
                {}
            )
        )

        if not isinstance(
            existing_knowledge,
            dict,
        ):
            existing_knowledge = {}

        enriched.metadata[
            "knowledge"
        ] = cls._merge_missing(
            existing=existing_knowledge,
            defaults=knowledge_metadata,
        )

        return enriched

    @classmethod
    def enrich_many(
        cls,
        findings: list[
            SecurityFinding
        ],
    ) -> list[
        SecurityFinding
    ]:
        return [
            cls.enrich(
                finding
            )
            for finding in findings
        ]

    @staticmethod
    def _normalize_rule_id(
        rule_id: str,
    ) -> str:
        return str(
            rule_id or ""
        ).strip().upper()

    @classmethod
    def _merge_missing(
        cls,
        *,
        existing: dict[str, Any],
        defaults: dict[str, Any],
    ) -> dict[str, Any]:
        merged = deepcopy(
            existing
        )

        for key, value in defaults.items():
            if key not in merged:
                merged[key] = deepcopy(
                    value
                )
                continue

            if (
                isinstance(
                    merged[key],
                    dict,
                )
                and isinstance(
                    value,
                    dict,
                )
            ):
                merged[key] = (
                    cls._merge_missing(
                        existing=merged[key],
                        defaults=value,
                    )
                )

        return merged
