from __future__ import annotations

from app.services.discovery.models import EndpointDiscovery

from app.services.security.models import (
    FindingCategory,
    SecurityConfidence,
    SecurityFinding,
    SecuritySeverity,
    SourceLocation,
)


SAFE_METHODS = {
    "GET",
    "HEAD",
    "OPTIONS",
}


class AuthorizationAnalyzer:

    RULE_ID = "AUTH-002"

    def analyze(
        self,
        endpoint: EndpointDiscovery,
    ) -> list[SecurityFinding]:

        findings: list[
            SecurityFinding
        ] = []

        authenticated = bool(
            endpoint.authentication_required
        )

        if not authenticated:
            return findings

        permission_required = bool(
            endpoint.permission_required
        )

        security_scopes = list(
            endpoint.security_scopes or []
        )

        if (
            permission_required
            or security_scopes
        ):
            return findings

        method = endpoint.method.upper()

        severity = (
            SecuritySeverity.MEDIUM
            if method in SAFE_METHODS
            else SecuritySeverity.HIGH
        )

        findings.append(
            SecurityFinding(
                rule_id=self.RULE_ID,
                title="Authorization Missing",
                description=(
                    "The endpoint requires "
                    "authentication but no "
                    "authorization rule, "
                    "permission or scope "
                    "was detected."
                ),
                category=(
                    FindingCategory.AUTHORIZATION
                ),
                severity=severity,
                confidence=(
                    SecurityConfidence.HIGH
                ),
                remediation=(
                    "Enforce role, permission "
                    "or scope validation before "
                    "processing the request."
                ),
                owasp_reference="API5:2023",
                cwe_id="CWE-862",
                endpoint_method=method,
                endpoint_path=self._path(endpoint),
                evidence=(
                    "permission_required=False "
                    "and no security scopes found."
                ),
                source_location=SourceLocation(
                    file_path=endpoint.file_path,
                    line_number=endpoint.line_number,
                    function_name=endpoint.function_name,
                ),
            )
        )

        return findings

    @staticmethod
    def _path(
        endpoint: EndpointDiscovery,
    ) -> str:

        prefix = (
            endpoint.router_prefix or ""
        ).rstrip("/")

        path = (
            endpoint.path or ""
        ).lstrip("/")

        if prefix and path:
            return f"{prefix}/{path}"

        if prefix:
            return prefix

        if path:
            return f"/{path}"

        return "/"
