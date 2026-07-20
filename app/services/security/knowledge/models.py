from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SecurityKnowledgeRecord:
    rule_id: str
    title: str
    category: str
    description: str
    remediation: str

    owasp_api_categories: tuple[str, ...] = field(
        default_factory=tuple
    )

    cwe_ids: tuple[str, ...] = field(
        default_factory=tuple
    )

    capec_ids: tuple[str, ...] = field(
        default_factory=tuple
    )

    references: tuple[str, ...] = field(
        default_factory=tuple
    )

    cvss_vector: str | None = None
    cvss_score: float | None = None

    compliance: dict[
        str,
        tuple[str, ...],
    ] = field(
        default_factory=dict
    )
