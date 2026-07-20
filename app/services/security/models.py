from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from enum import StrEnum
from typing import Any


class SecuritySeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingCategory(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    FILE_UPLOAD = "file_upload"
    RATE_LIMITING = "rate_limiting"
    DATA_EXPOSURE = "data_exposure"
    ERROR_HANDLING = "error_handling"
    SECURITY_CONFIGURATION = "security_configuration"
    TRANSPORT_SECURITY = "transport_security"
    BUSINESS_LOGIC = "business_logic"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


SEVERITY_WEIGHTS: dict[SecuritySeverity, int] = {
    SecuritySeverity.CRITICAL: 25,
    SecuritySeverity.HIGH: 15,
    SecuritySeverity.MEDIUM: 8,
    SecuritySeverity.LOW: 3,
    SecuritySeverity.INFO: 0,
}


@dataclass(slots=True, frozen=True)
class SourceLocation:
    file_path: str
    line_number: int | None = None
    column_number: int | None = None
    function_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "function_name": self.function_name,
        }


@dataclass(slots=True)
class SecurityFinding:
    rule_id: str
    title: str
    description: str
    category: FindingCategory
    severity: SecuritySeverity
    confidence: SecurityConfidence
    remediation: str
    owasp_reference: str | None = None
    cwe_id: str | None = None
    endpoint_method: str | None = None
    endpoint_path: str | None = None
    evidence: str | None = None
    source_location: SourceLocation | None = None
    status: FindingStatus = FindingStatus.OPEN
    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    @property
    def endpoint_identifier(self) -> str | None:
        if not self.endpoint_method or not self.endpoint_path:
            return None

        return (
            f"{self.endpoint_method.upper()} "
            f"{self.endpoint_path}"
        )

    @property
    def penalty(self) -> int:
        return SEVERITY_WEIGHTS[
            self.severity
        ]

    def fingerprint(self) -> tuple[
        str,
        str | None,
        str | None,
        str | None,
        int | None,
    ]:
        return (
            self.rule_id,
            (
                self.endpoint_method.upper()
                if self.endpoint_method
                else None
            ),
            self.endpoint_path,
            (
                self.source_location.file_path
                if self.source_location
                else None
            ),
            (
                self.source_location.line_number
                if self.source_location
                else None
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "remediation": self.remediation,
            "owasp_reference": self.owasp_reference,
            "cwe_id": self.cwe_id,
            "endpoint_method": self.endpoint_method,
            "endpoint_path": self.endpoint_path,
            "endpoint_identifier": (
                self.endpoint_identifier
            ),
            "evidence": self.evidence,
            "source_location": (
                self.source_location.to_dict()
                if self.source_location
                else None
            ),
            "status": self.status.value,
            "penalty": self.penalty,
            "metadata": dict(
                self.metadata,
            ),
        }


@dataclass(slots=True)
class EndpointSecurityAssessment:
    method: str
    path: str
    findings: list[SecurityFinding] = field(
        default_factory=list,
    )
    score: int = 100
    severity: SecuritySeverity = (
        SecuritySeverity.INFO
    )
    authenticated: bool = False
    authorization_required: bool = False
    security_schemes: list[str] = field(
        default_factory=list,
    )
    security_scopes: list[str] = field(
        default_factory=list,
    )

    @property
    def identifier(self) -> str:
        return (
            f"{self.method.upper()} "
            f"{self.path}"
        )

    def add_finding(
        self,
        finding: SecurityFinding,
    ) -> None:
        existing_fingerprints = {
            existing.fingerprint()
            for existing in self.findings
        }

        if (
            finding.fingerprint()
            in existing_fingerprints
        ):
            return

        self.findings.append(
            finding,
        )

    def recalculate(self) -> None:
        total_penalty = sum(
            finding.penalty
            for finding in self.findings
            if finding.status
            == FindingStatus.OPEN
        )

        self.score = max(
            0,
            min(
                100,
                100 - total_penalty,
            ),
        )

        self.severity = (
            severity_from_score(
                self.score,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method.upper(),
            "path": self.path,
            "identifier": self.identifier,
            "score": self.score,
            "severity": self.severity.value,
            "authenticated": self.authenticated,
            "authorization_required": (
                self.authorization_required
            ),
            "security_schemes": list(
                self.security_schemes,
            ),
            "security_scopes": list(
                self.security_scopes,
            ),
            "finding_count": len(
                self.findings,
            ),
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
        }


@dataclass(slots=True)
class SecurityAnalysisResult:
    project_id: int | None = None
    project_name: str | None = None
    framework: str | None = None
    assessments: list[
        EndpointSecurityAssessment
    ] = field(
        default_factory=list,
    )
    score: int = 100
    severity: SecuritySeverity = (
        SecuritySeverity.INFO
    )
    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    @property
    def findings(self) -> list[
        SecurityFinding
    ]:
        return [
            finding
            for assessment in self.assessments
            for finding in assessment.findings
        ]

    def add_assessment(
        self,
        assessment: EndpointSecurityAssessment,
    ) -> None:
        assessment.recalculate()

        existing_index = next(
            (
                index
                for index, current
                in enumerate(
                    self.assessments,
                )
                if (
                    current.method.upper()
                    == assessment.method.upper()
                    and current.path
                    == assessment.path
                )
            ),
            None,
        )

        if existing_index is None:
            self.assessments.append(
                assessment,
            )
        else:
            self.assessments[
                existing_index
            ] = assessment

    def recalculate(self) -> None:
        for assessment in self.assessments:
            assessment.recalculate()

        if not self.assessments:
            self.score = 100
            self.severity = (
                SecuritySeverity.INFO
            )
            return

        endpoint_scores = [
            assessment.score
            for assessment
            in self.assessments
        ]

        average_score = round(
            sum(endpoint_scores)
            / len(endpoint_scores)
        )

        critical_findings = sum(
            1
            for finding in self.findings
            if (
                finding.status
                == FindingStatus.OPEN
                and finding.severity
                == SecuritySeverity.CRITICAL
            )
        )

        high_findings = sum(
            1
            for finding in self.findings
            if (
                finding.status
                == FindingStatus.OPEN
                and finding.severity
                == SecuritySeverity.HIGH
            )
        )

        critical_penalty = min(
            30,
            critical_findings * 10,
        )

        high_penalty = min(
            15,
            high_findings * 3,
        )

        self.score = max(
            0,
            min(
                100,
                (
                    average_score
                    - critical_penalty
                    - high_penalty
                ),
            ),
        )

        self.severity = (
            severity_from_score(
                self.score,
            )
        )

    def severity_counts(
        self,
    ) -> dict[str, int]:
        counts = {
            severity.value: 0
            for severity
            in SecuritySeverity
        }

        for finding in self.findings:
            if (
                finding.status
                != FindingStatus.OPEN
            ):
                continue

            counts[
                finding.severity.value
            ] += 1

        return counts

    def category_counts(
        self,
    ) -> dict[str, int]:
        counts = {
            category.value: 0
            for category
            in FindingCategory
        }

        for finding in self.findings:
            if (
                finding.status
                != FindingStatus.OPEN
            ):
                continue

            counts[
                finding.category.value
            ] += 1

        return counts

    def to_dict(self) -> dict[str, Any]:
        self.recalculate()

        return {
            "project_id": self.project_id,
            "project_name": self.project_name,
            "framework": self.framework,
            "score": self.score,
            "severity": self.severity.value,
            "endpoint_count": len(
                self.assessments,
            ),
            "finding_count": len(
                self.findings,
            ),
            "severity_counts": (
                self.severity_counts()
            ),
            "category_counts": (
                self.category_counts()
            ),
            "assessments": [
                assessment.to_dict()
                for assessment
                in self.assessments
            ],
            "metadata": dict(
                self.metadata,
            ),
        }


def severity_from_score(
    score: int,
) -> SecuritySeverity:
    normalized_score = max(
        0,
        min(
            100,
            score,
        ),
    )

    if normalized_score < 30:
        return SecuritySeverity.CRITICAL

    if normalized_score < 50:
        return SecuritySeverity.HIGH

    if normalized_score < 70:
        return SecuritySeverity.MEDIUM

    if normalized_score < 90:
        return SecuritySeverity.LOW

    return SecuritySeverity.INFO
