from app.services.security.source_analysis.analyzers.fastapi_authorization import (
    FastAPIAuthorizationSecurityAnalyzer,
)
from app.services.security.source_analysis.analyzers import (
    FastAPIAuthenticationSecurityAnalyzer,
    FastAPIEndpointSecurityAnalyzer,
    PythonASTSecurityAnalyzer,
    PythonConfigurationSecurityAnalyzer,
)
from app.services.security.source_analysis.base import (
    SourceAnalyzer,
)
from app.services.security.source_analysis.context import (
    SourceAnalysisContext,
)
from app.services.security.source_analysis.loader import (
    SourceFileLoader,
)
from app.services.security.source_analysis.models import (
    SourceAnalysisResult,
    SourceFile,
    SourceIssue,
    SourceIssueConfidence,
    SourceIssueSeverity,
    SourceLocation,
)
from app.services.security.source_analysis.registry import (
    SourceAnalyzerRegistry,
)
from app.services.security.source_analysis.service import (
    SourceAnalysisService,
)

registry = SourceAnalyzerRegistry(
    [
        PythonASTSecurityAnalyzer(),
        PythonConfigurationSecurityAnalyzer(),
        FastAPIEndpointSecurityAnalyzer(),
        FastAPIAuthenticationSecurityAnalyzer(),
        FastAPIAuthorizationSecurityAnalyzer(),
    ],
)

__all__ = [
    "FastAPIAuthorizationSecurityAnalyzer",
    "FastAPIAuthenticationSecurityAnalyzer",
    "FastAPIEndpointSecurityAnalyzer",
    "PythonASTSecurityAnalyzer",
    "PythonConfigurationSecurityAnalyzer",
    "SourceAnalysisContext",
    "SourceAnalysisResult",
    "SourceAnalysisService",
    "SourceAnalyzer",
    "SourceAnalyzerRegistry",
    "SourceFile",
    "SourceFileLoader",
    "SourceIssue",
    "SourceIssueConfidence",
    "SourceIssueSeverity",
    "SourceLocation",
    "registry",
]
