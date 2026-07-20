from __future__ import annotations

from app.services.security.models import (
    EndpointSecurityAssessment,
    SecurityAnalysisResult,
    SecuritySeverity,
)


SEVERITY_PENALTIES: dict[SecuritySeverity, int] = {
    SecuritySeverity.CRITICAL: 40,
    SecuritySeverity.HIGH: 25,
    SecuritySeverity.MEDIUM: 10,
    SecuritySeverity.LOW: 5,
    SecuritySeverity.INFO: 1,
}


class SecurityScoreCalculator:
    @classmethod
    def score_endpoint(
        cls,
        assessment: EndpointSecurityAssessment,
    ) -> EndpointSecurityAssessment:
        score = 100

        for finding in assessment.findings:
            score -= SEVERITY_PENALTIES.get(
                finding.severity,
                0,
            )

        assessment.score = max(
            0,
            score,
        )

        assessment.severity = (
            cls._severity_from_score(
                assessment.score
            )
        )

        return assessment

    @classmethod
    def score_project(
        cls,
        result: SecurityAnalysisResult,
    ) -> SecurityAnalysisResult:
        assessments = [
            cls.score_endpoint(a)
            for a in result.assessments
        ]

        if assessments:
            average_score = round(
                sum(
                    a.score
                    for a in assessments
                )
                / len(assessments)
            )
        else:
            average_score = 100

        result.assessments = assessments
        result.score = average_score
        result.severity = (
            cls._severity_from_score(
                average_score
            )
        )

        result.metadata.update(
            {
                "average_score": average_score,
                "endpoint_count": len(
                    assessments
                ),
                "finding_count": sum(
                    len(a.findings)
                    for a in assessments
                ),
            }
        )

        return result

    @staticmethod
    def _severity_from_score(
        score: int,
    ) -> SecuritySeverity:
        if score >= 90:
            return SecuritySeverity.INFO

        if score >= 75:
            return SecuritySeverity.LOW

        if score >= 50:
            return SecuritySeverity.MEDIUM

        if score >= 25:
            return SecuritySeverity.HIGH

        return SecuritySeverity.CRITICAL
