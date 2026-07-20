from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from app.services.discovery.models import EndpointDiscovery
from app.services.security.authentication import AuthenticationAnalyzer
from app.services.security.authorization import AuthorizationAnalyzer
from app.services.security.file_upload import FileUploadAnalyzer
from app.services.security.knowledge import SecurityKnowledgeEnricher
from app.services.security.knowledge.project_summary import (
    ProjectKnowledgeSummary,
)
from app.services.security.models import (
    EndpointSecurityAssessment,
    SecurityAnalysisResult,
    SecurityFinding,
)
from app.services.security.post_processing import (
    SecurityFindingProcessor,
)
from app.services.security.scoring import (
    SecurityScoreCalculator,
)
from app.services.security.validation import ValidationAnalyzer


class EndpointAnalyzer(Protocol):
    def analyze(
        self,
        endpoint: EndpointDiscovery,
    ) -> list[SecurityFinding]:
        ...


class SecurityAnalyzer:
    def __init__(
        self,
        analyzers: Iterable[EndpointAnalyzer] | None = None,
    ) -> None:
        self.analyzers = tuple(
            analyzers
            if analyzers is not None
            else (
                AuthenticationAnalyzer(),
                AuthorizationAnalyzer(),
                ValidationAnalyzer(),
                FileUploadAnalyzer(),
            )
        )

    def analyze_endpoint(
        self,
        endpoint: EndpointDiscovery,
    ) -> EndpointSecurityAssessment:

        findings: list[SecurityFinding] = []

        for analyzer in self.analyzers:
            findings.extend(
                analyzer.analyze(endpoint)
            )

        findings = SecurityKnowledgeEnricher.enrich_many(
            findings
        )

        findings = (
            SecurityFindingProcessor.normalize_findings(
                findings
            )
        )

        assessment = EndpointSecurityAssessment(
            method=str(endpoint.method).upper(),
            path=self._build_path(endpoint),
            findings=findings,
            authenticated=bool(
                endpoint.authentication_required
            ),
            authorization_required=bool(
                endpoint.permission_required
            ),
            security_schemes=list(
                endpoint.security_schemes or []
            ),
            security_scopes=list(
                endpoint.security_scopes or []
            ),
        )

        return SecurityScoreCalculator.score_endpoint(
            assessment
        )

    def analyze_endpoints(
        self,
        endpoints: Iterable[EndpointDiscovery],
    ) -> SecurityAnalysisResult:

        assessments = [
            self.analyze_endpoint(endpoint)
            for endpoint in endpoints
        ]

        result = SecurityAnalysisResult(
            assessments=assessments,
            metadata={
                "endpoint_count": len(assessments),
                "analyzer_count": len(self.analyzers),
            },
        )

        result = (
            SecurityFindingProcessor.enrich_result(
                result
            )
        )

        result = (
            ProjectKnowledgeSummary.enrich(
                result
            )
        )

        result = (
            SecurityScoreCalculator.score_project(
                result
            )
        )

        return result

    @staticmethod
    def _build_path(
        endpoint: EndpointDiscovery,
    ) -> str:

        prefix = (
            str(
                getattr(
                    endpoint,
                    "router_prefix",
                    "",
                )
                or ""
            )
            .rstrip("/")
        )

        path = (
            str(
                getattr(
                    endpoint,
                    "path",
                    "",
                )
                or ""
            )
            .lstrip("/")
        )

        if prefix and path:
            full = f"{prefix}/{path}"
        elif prefix:
            full = prefix
        elif path:
            full = "/" + path
        else:
            full = "/"

        while "//" in full:
            full = full.replace("//", "/")

        if (
            full != "/"
            and full.endswith("/")
        ):
            full = full[:-1]

        if not full.startswith("/"):
            full = "/" + full

        return full
