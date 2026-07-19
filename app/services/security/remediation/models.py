from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from enum import StrEnum
from typing import Any


class RemediationPriority(StrEnum):
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class RemediationEffort(StrEnum):
    TRIVIAL = "trivial"
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"
    EXTRA_LARGE = "extra_large"


class RemediationStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ACCEPTED_RISK = "accepted_risk"
    NOT_APPLICABLE = "not_applicable"


@dataclass(slots=True, frozen=True)
class SecureCodeExample:
    framework: str
    language: str
    title: str
    code: str
    explanation: str | None = None
    file_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "language": self.language,
            "title": self.title,
            "code": self.code,
            "explanation": self.explanation,
            "file_hint": self.file_hint,
        }


@dataclass(slots=True)
class RemediationGuidance:
    rule_id: str
    title: str
    summary: str
    business_impact: str
    technical_impact: str
    recommended_fix: str
    priority: RemediationPriority
    effort: RemediationEffort
    status: RemediationStatus = (
        RemediationStatus.PENDING
    )
    implementation_steps: list[str] = field(
        default_factory=list,
    )
    validation_steps: list[str] = field(
        default_factory=list,
    )
    code_examples: list[
        SecureCodeExample
    ] = field(
        default_factory=list,
    )
    references: list[str] = field(
        default_factory=list,
    )
    tags: list[str] = field(
        default_factory=list,
    )
    estimated_minutes_min: int | None = None
    estimated_minutes_max: int | None = None
    risk_reduction_percent: float | None = None
    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    @property
    def estimated_time_label(self) -> str | None:
        minimum = self.estimated_minutes_min
        maximum = self.estimated_minutes_max

        if minimum is None and maximum is None:
            return None

        if minimum is not None and maximum is not None:
            if minimum == maximum:
                return f"{minimum} minutes"

            return f"{minimum}–{maximum} minutes"

        if minimum is not None:
            return f"At least {minimum} minutes"

        return f"Up to {maximum} minutes"

    def add_code_example(
        self,
        example: SecureCodeExample,
    ) -> None:
        fingerprint = (
            example.framework.lower(),
            example.language.lower(),
            example.title.lower(),
        )

        existing = {
            (
                item.framework.lower(),
                item.language.lower(),
                item.title.lower(),
            )
            for item in self.code_examples
        }

        if fingerprint not in existing:
            self.code_examples.append(
                example,
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "summary": self.summary,
            "business_impact": self.business_impact,
            "technical_impact": self.technical_impact,
            "recommended_fix": self.recommended_fix,
            "priority": self.priority.value,
            "effort": self.effort.value,
            "status": self.status.value,
            "implementation_steps": list(
                self.implementation_steps,
            ),
            "validation_steps": list(
                self.validation_steps,
            ),
            "code_examples": [
                example.to_dict()
                for example in self.code_examples
            ],
            "references": list(
                self.references,
            ),
            "tags": list(
                self.tags,
            ),
            "estimated_minutes_min": (
                self.estimated_minutes_min
            ),
            "estimated_minutes_max": (
                self.estimated_minutes_max
            ),
            "estimated_time_label": (
                self.estimated_time_label
            ),
            "risk_reduction_percent": (
                self.risk_reduction_percent
            ),
            "metadata": dict(
                self.metadata,
            ),
        }


@dataclass(slots=True)
class FindingRemediation:
    finding_rule_id: str
    endpoint_method: str | None
    endpoint_path: str | None
    guidance: RemediationGuidance
    framework: str | None = None
    customized: bool = False
    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    @property
    def endpoint_identifier(self) -> str | None:
        if (
            not self.endpoint_method
            or not self.endpoint_path
        ):
            return None

        return (
            f"{self.endpoint_method.upper()} "
            f"{self.endpoint_path}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_rule_id": (
                self.finding_rule_id
            ),
            "endpoint_method": (
                self.endpoint_method.upper()
                if self.endpoint_method
                else None
            ),
            "endpoint_path": self.endpoint_path,
            "endpoint_identifier": (
                self.endpoint_identifier
            ),
            "framework": self.framework,
            "customized": self.customized,
            "guidance": self.guidance.to_dict(),
            "metadata": dict(
                self.metadata,
            ),
        }
