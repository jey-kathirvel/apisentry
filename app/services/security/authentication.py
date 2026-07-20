from __future__ import annotations

from app.services.discovery.models import (
    EndpointDiscovery,
)
from app.services.security.models import (
    FindingCategory,
    SecurityConfidence,
    SecurityFinding,
    SecuritySeverity,
    SourceLocation,
)


SAFE_METHODS = frozenset(
    {
        "GET",
        "HEAD",
        "OPTIONS",
    }
)

PUBLIC_PATH_PREFIXES = (
    "/health",
    "/docs",
    "/openapi",
    "/redoc",
    "/favicon",
)


class AuthenticationAnalyzer:
    """
    Detect endpoints that do not declare authentication.

    AUTH-001:
        Missing or potentially missing authentication.
    """

    RULE_ID = "AUTH-001"

    def analyze(
        self,
        endpoint: EndpointDiscovery,
    ) -> list[SecurityFinding]:
        method = str(
            endpoint.method or "",
        ).upper()

        path = self._build_endpoint_path(
            endpoint,
        )

        if self._is_public_system_path(
            path,
        ):
            return []

        authentication_required = bool(
            endpoint.authentication_required
        )

        if authentication_required:
            return []

        source_location = SourceLocation(
            file_path=str(
                endpoint.file_path or "",
            ),
            line_number=endpoint.line_number,
            function_name=(
                endpoint.function_name
            ),
        )

        if method in SAFE_METHODS:
            return [
                SecurityFinding(
                    rule_id=self.RULE_ID,
                    title=(
                        "Unauthenticated Read Endpoint"
                    ),
                    description=(
                        "The read endpoint does not "
                        "declare an authentication "
                        "requirement."
                    ),
                    category=(
                        FindingCategory.AUTHENTICATION
                    ),
                    severity=SecuritySeverity.INFO,
                    confidence=(
                        SecurityConfidence.MEDIUM
                    ),
                    remediation=(
                        "Confirm that the endpoint is "
                        "intentionally public. Otherwise, "
                        "require a verified authentication "
                        "dependency before returning data."
                    ),
                    owasp_reference="API2:2023",
                    cwe_id="CWE-306",
                    endpoint_method=method,
                    endpoint_path=path,
                    evidence=(
                        "authentication_required=False "
                        "and no authentication dependency "
                        "was discovered."
                    ),
                    source_location=source_location,
                    metadata={
                        "authentication_required": False,
                        "security_schemes": list(
                            endpoint.security_schemes
                            or []
                        ),
                        "dependencies": list(
                            endpoint.dependencies
                            or []
                        ),
                    },
                )
            ]

        return [
            SecurityFinding(
                rule_id=self.RULE_ID,
                title="Authentication Missing",
                description=(
                    "The endpoint performs a state-changing "
                    "operation without a discovered "
                    "authentication requirement."
                ),
                category=(
                    FindingCategory.AUTHENTICATION
                ),
                severity=SecuritySeverity.HIGH,
                confidence=SecurityConfidence.HIGH,
                remediation=(
                    "Require an authentication dependency, "
                    "such as Depends(get_current_user), "
                    "Security(...), HTTPBearer, OAuth2, or "
                    "an API-key security dependency."
                ),
                owasp_reference="API2:2023",
                cwe_id="CWE-306",
                endpoint_method=method,
                endpoint_path=path,
                evidence=(
                    "authentication_required=False "
                    "and no authentication dependency "
                    "was discovered."
                ),
                source_location=source_location,
                metadata={
                    "authentication_required": False,
                    "security_schemes": list(
                        endpoint.security_schemes
                        or []
                    ),
                    "dependencies": list(
                        endpoint.dependencies
                        or []
                    ),
                },
            )
        ]

    @staticmethod
    def _build_endpoint_path(
        endpoint: EndpointDiscovery,
    ) -> str:
        prefix = str(
            endpoint.router_prefix or "",
        ).strip()

        route_path = str(
            endpoint.path or "",
        ).strip()

        prefix = prefix.rstrip("/")
        route_path = route_path.lstrip("/")

        if prefix and route_path:
            complete_path = (
                f"{prefix}/{route_path}"
            )
        elif prefix:
            complete_path = prefix
        elif route_path:
            complete_path = (
                f"/{route_path}"
            )
        else:
            complete_path = "/"

        if not complete_path.startswith("/"):
            complete_path = (
                f"/{complete_path}"
            )

        while "//" in complete_path:
            complete_path = (
                complete_path.replace(
                    "//",
                    "/",
                )
            )

        if (
            complete_path != "/"
            and complete_path.endswith("/")
        ):
            complete_path = (
                complete_path.rstrip("/")
            )

        return complete_path

    @staticmethod
    def _is_public_system_path(
        path: str,
    ) -> bool:
        normalized_path = (
            path.lower().rstrip("/") or "/"
        )

        for prefix in PUBLIC_PATH_PREFIXES:
            normalized_prefix = (
                prefix.lower().rstrip("/")
            )

            if (
                normalized_path
                == normalized_prefix
                or normalized_path.startswith(
                    f"{normalized_prefix}/"
                )
            ):
                return True

        return False
