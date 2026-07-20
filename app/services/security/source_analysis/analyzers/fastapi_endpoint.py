from __future__ import annotations

import ast
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from app.services.security.source_analysis.base import (
    SourceAnalyzer,
)
from app.services.security.source_analysis.context import (
    SourceAnalysisContext,
)
from app.services.security.source_analysis.models import (
    SourceAnalysisResult,
    SourceFile,
    SourceIssue,
    SourceIssueConfidence,
    SourceIssueSeverity,
    SourceLocation,
)


@dataclass(
    slots=True,
    frozen=True,
)
class FastAPIEndpointRule:
    rule_id: str
    title: str
    description: str
    category: str
    severity: SourceIssueSeverity
    confidence: SourceIssueConfidence
    remediation: str
    cwe_id: str | None = None
    owasp_reference: str | None = None
    metadata: dict[str, Any] = field(
        default_factory=dict,
    )


@dataclass(
    slots=True,
    frozen=True,
)
class FastAPIEndpoint:
    method: str
    path: str
    function_name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    decorator: ast.Call
    dependencies: tuple[str, ...]
    parameters: tuple[str, ...]
    parameter_annotations: tuple[str, ...]


class FastAPIEndpointSecurityAnalyzer(
    SourceAnalyzer,
):
    name = "fastapi-endpoint-security"

    languages = (
        "python",
    )

    frameworks = (
        "fastapi",
    )

    priority = 80

    SENSITIVE_ENDPOINT_RULE = FastAPIEndpointRule(
        rule_id="FASTAPI-AUTH-001",
        title="Sensitive FastAPI endpoint lacks authentication",
        description=(
            "A security-sensitive FastAPI endpoint does not declare "
            "an authentication or authorization dependency."
        ),
        category="authentication",
        severity=SourceIssueSeverity.HIGH,
        confidence=SourceIssueConfidence.MEDIUM,
        remediation=(
            "Protect the endpoint using a FastAPI dependency such as "
            "Depends(get_current_user), Security(...), or an equivalent "
            "authenticated principal dependency."
        ),
        cwe_id="CWE-306",
        owasp_reference="API2:2023",
    )

    DELETE_ENDPOINT_RULE = FastAPIEndpointRule(
        rule_id="FASTAPI-AUTH-002",
        title="Destructive endpoint lacks authorization",
        description=(
            "A DELETE endpoint or destructive operation does not declare "
            "an authentication or authorization dependency."
        ),
        category="authorization",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Require authentication and enforce object-level or role-based "
            "authorization before performing the destructive operation."
        ),
        cwe_id="CWE-862",
        owasp_reference="API1:2023",
    )

    FILE_UPLOAD_RULE = FastAPIEndpointRule(
        rule_id="FASTAPI-FILE-001",
        title="File upload lacks visible validation",
        description=(
            "A FastAPI upload endpoint accepts UploadFile or File input "
            "without visible file type or size validation."
        ),
        category="file-upload",
        severity=SourceIssueSeverity.HIGH,
        confidence=SourceIssueConfidence.MEDIUM,
        remediation=(
            "Validate the uploaded file extension, MIME type, actual file "
            "signature, and maximum permitted size before storage or "
            "processing. Generate server-side filenames and store uploads "
            "outside executable directories."
        ),
        cwe_id="CWE-434",
        owasp_reference="API8:2023",
    )

    EXCEPTION_LEAK_RULE = FastAPIEndpointRule(
        rule_id="FASTAPI-ERROR-001",
        title="Internal exception exposed to API client",
        description=(
            "The endpoint appears to expose raw exception text through an "
            "HTTP response or HTTPException detail."
        ),
        category="information-disclosure",
        severity=SourceIssueSeverity.MEDIUM,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Log internal exception details server-side and return a stable, "
            "non-sensitive error message and correlation identifier to the "
            "client."
        ),
        cwe_id="CWE-209",
        owasp_reference="API8:2023",
    )

    OPEN_REDIRECT_RULE = FastAPIEndpointRule(
        rule_id="FASTAPI-REDIRECT-001",
        title="Potential unvalidated redirect",
        description=(
            "A redirect response appears to use a request-controlled value "
            "directly as the destination URL."
        ),
        category="input-validation",
        severity=SourceIssueSeverity.MEDIUM,
        confidence=SourceIssueConfidence.MEDIUM,
        remediation=(
            "Allow redirects only to approved relative paths or validate "
            "the destination against a strict server-side allowlist."
        ),
        cwe_id="CWE-601",
        owasp_reference="API10:2023",
    )

    SENSITIVE_PATH_PARTS = {
        "account",
        "admin",
        "billing",
        "booking",
        "customer",
        "document",
        "invoice",
        "order",
        "password",
        "payment",
        "profile",
        "project",
        "report",
        "role",
        "security",
        "settings",
        "token",
        "transaction",
        "upload",
        "user",
    }

    AUTH_DEPENDENCY_PARTS = {
        "auth",
        "authorize",
        "current_user",
        "get_user",
        "jwt",
        "login",
        "permission",
        "principal",
        "require_",
        "require_user",
        "role",
        "security",
        "session_user",
        "token",
    }

    FILE_VALIDATION_PARTS = {
        "allowed_extension",
        "allowed_extensions",
        "content_type",
        "file_size",
        "filesize",
        "max_file_size",
        "mime",
        "mimetype",
        "size_limit",
        "validate_file",
        "validate_upload",
    }

    HTTP_METHODS = {
        "delete",
        "get",
        "head",
        "options",
        "patch",
        "post",
        "put",
    }

    def supports(
        self,
        *,
        language: str | None = None,
        framework: str | None = None,
    ) -> bool:
        normalized_language = (
            language
            or ""
        ).strip().lower()

        normalized_framework = (
            framework
            or ""
        ).strip().lower()

        language_supported = (
            not normalized_language
            or normalized_language == "python"
        )

        framework_supported = (
            not normalized_framework
            or normalized_framework == "fastapi"
        )

        return (
            language_supported
            and framework_supported
        )

    def analyze(
        self,
        *,
        files: list[SourceFile],
        context: SourceAnalysisContext,
    ) -> SourceAnalysisResult:
        issues: list[SourceIssue] = []
        errors: list[str] = []
        files_scanned = 0
        endpoint_count = 0

        for source_file in files:
            if source_file.language != "python":
                continue

            files_scanned += 1

            try:
                tree = ast.parse(
                    source_file.content,
                    filename=source_file.relative_path,
                )
            except SyntaxError as exc:
                errors.append(
                    self._format_syntax_error(
                        source_file=source_file,
                        error=exc,
                    ),
                )
                continue

            visitor = _FastAPIEndpointVisitor(
                source_file=source_file,
            )

            visitor.visit(
                tree,
            )

            endpoint_count += len(
                visitor.endpoints,
            )

            issues.extend(
                visitor.issues,
            )

        result = SourceAnalysisResult(
            analyzer=self.name,
            files_scanned=files_scanned,
            issues=issues,
            errors=errors,
            metadata={
                "engine": "python-ast",
                "framework": "fastapi",
                "endpoint_count": endpoint_count,
                "rule_ids": [
                    "FASTAPI-AUTH-001",
                    "FASTAPI-AUTH-002",
                    "FASTAPI-FILE-001",
                    "FASTAPI-ERROR-001",
                    "FASTAPI-REDIRECT-001",
                ],
            },
        )

        result.deduplicate()

        return result

    @staticmethod
    def _format_syntax_error(
        *,
        source_file: SourceFile,
        error: SyntaxError,
    ) -> str:
        return (
            f"{source_file.relative_path}:"
            f"{error.lineno or 0}: SyntaxError: "
            f"{error.msg or 'invalid syntax'}"
        )


class _FastAPIEndpointVisitor(
    ast.NodeVisitor,
):
    def __init__(
        self,
        *,
        source_file: SourceFile,
    ) -> None:
        self.source_file = source_file
        self.endpoints: list[FastAPIEndpoint] = []
        self.issues: list[SourceIssue] = []
        self._class_stack: list[str] = []

    def visit_ClassDef(
        self,
        node: ast.ClassDef,
    ) -> Any:
        self._class_stack.append(
            node.name,
        )

        self.generic_visit(
            node,
        )

        self._class_stack.pop()

        return node

    def visit_FunctionDef(
        self,
        node: ast.FunctionDef,
    ) -> Any:
        self._inspect_endpoint(
            node,
        )

        self.generic_visit(
            node,
        )

        return node

    def visit_AsyncFunctionDef(
        self,
        node: ast.AsyncFunctionDef,
    ) -> Any:
        self._inspect_endpoint(
            node,
        )

        self.generic_visit(
            node,
        )

        return node

    def _inspect_endpoint(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for decorator in node.decorator_list:
            endpoint = self._build_endpoint(
                node=node,
                decorator=decorator,
            )

            if endpoint is None:
                continue

            self.endpoints.append(
                endpoint,
            )

            self._inspect_authentication(
                endpoint,
            )

            self._inspect_file_upload(
                endpoint,
            )

            self._inspect_exception_leakage(
                endpoint,
            )

            self._inspect_redirects(
                endpoint,
            )

    def _build_endpoint(
        self,
        *,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        decorator: ast.AST,
    ) -> FastAPIEndpoint | None:
        if not isinstance(
            decorator,
            ast.Call,
        ):
            return None

        decorator_name = self._call_name(
            decorator.func,
        )

        method = decorator_name.rsplit(
            ".",
            1,
        )[-1].lower()

        if method not in (
            FastAPIEndpointSecurityAnalyzer
            .HTTP_METHODS
        ):
            return None

        path = self._endpoint_path(
            decorator,
        )

        dependencies = self._collect_dependencies(
            node=node,
            decorator=decorator,
        )

        parameters: list[str] = []
        annotations: list[str] = []

        all_arguments = [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]

        for argument in all_arguments:
            parameters.append(
                argument.arg,
            )

            annotations.append(
                self._node_text(
                    argument.annotation,
                )
                or ""
            )

        return FastAPIEndpoint(
            method=method.upper(),
            path=path,
            function_name=node.name,
            node=node,
            decorator=decorator,
            dependencies=tuple(
                dependencies,
            ),
            parameters=tuple(
                parameters,
            ),
            parameter_annotations=tuple(
                annotations,
            ),
        )

    def _inspect_authentication(
        self,
        endpoint: FastAPIEndpoint,
    ) -> None:
        if self._has_auth_dependency(
            endpoint,
        ):
            return

        if endpoint.method == "DELETE":
            self._add_issue(
                rule=(
                    FastAPIEndpointSecurityAnalyzer
                    .DELETE_ENDPOINT_RULE
                ),
                endpoint=endpoint,
                node=endpoint.decorator,
            )
            return

        if self._is_sensitive_endpoint(
            endpoint,
        ):
            self._add_issue(
                rule=(
                    FastAPIEndpointSecurityAnalyzer
                    .SENSITIVE_ENDPOINT_RULE
                ),
                endpoint=endpoint,
                node=endpoint.decorator,
            )

    def _inspect_file_upload(
        self,
        endpoint: FastAPIEndpoint,
    ) -> None:
        accepts_file = any(
            (
                "uploadfile" in annotation.lower()
                or annotation.lower() == "bytes"
                or parameter.lower() in {
                    "file",
                    "files",
                    "upload",
                    "uploaded_file",
                }
            )
            for parameter, annotation in zip(
                endpoint.parameters,
                endpoint.parameter_annotations,
                strict=False,
            )
        )

        if not accepts_file:
            return

        function_text = (
            self._node_text(
                endpoint.node,
            )
            or ""
        ).lower()

        has_validation = any(
            marker in function_text
            for marker in (
                FastAPIEndpointSecurityAnalyzer
                .FILE_VALIDATION_PARTS
            )
        )

        if not has_validation:
            self._add_issue(
                rule=(
                    FastAPIEndpointSecurityAnalyzer
                    .FILE_UPLOAD_RULE
                ),
                endpoint=endpoint,
                node=endpoint.node,
            )

    def _inspect_exception_leakage(
        self,
        endpoint: FastAPIEndpoint,
    ) -> None:
        exception_names: set[str] = set()

        for child in ast.walk(
            endpoint.node,
        ):
            if not isinstance(
                child,
                ast.ExceptHandler,
            ):
                continue

            if child.name:
                exception_names.add(
                    child.name,
                )

        if not exception_names:
            return

        for child in ast.walk(
            endpoint.node,
        ):
            if self._contains_exception_text(
                child,
                exception_names,
            ):
                self._add_issue(
                    rule=(
                        FastAPIEndpointSecurityAnalyzer
                        .EXCEPTION_LEAK_RULE
                    ),
                    endpoint=endpoint,
                    node=child,
                )
                return

    def _inspect_redirects(
        self,
        endpoint: FastAPIEndpoint,
    ) -> None:
        parameter_names = set(
            endpoint.parameters,
        )

        for child in ast.walk(
            endpoint.node,
        ):
            if not isinstance(
                child,
                ast.Call,
            ):
                continue

            call_name = self._call_name(
                child.func,
            )

            if not call_name.endswith(
                "RedirectResponse",
            ):
                continue

            redirect_value: ast.AST | None = None

            if child.args:
                redirect_value = child.args[0]

            for keyword in child.keywords:
                if keyword.arg in {
                    "url",
                    "location",
                }:
                    redirect_value = keyword.value

            if (
                isinstance(
                    redirect_value,
                    ast.Name,
                )
                and redirect_value.id
                in parameter_names
            ):
                self._add_issue(
                    rule=(
                        FastAPIEndpointSecurityAnalyzer
                        .OPEN_REDIRECT_RULE
                    ),
                    endpoint=endpoint,
                    node=child,
                )
                return

    def _collect_dependencies(
        self,
        *,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        decorator: ast.Call,
    ) -> list[str]:
        dependencies: list[str] = []

        for child in ast.walk(
            node.args,
        ):
            if not isinstance(
                child,
                ast.Call,
            ):
                continue

            call_name = self._call_name(
                child.func,
            )

            if call_name.endswith(
                (
                    "Depends",
                    "Security",
                ),
            ):
                dependencies.append(
                    self._node_text(
                        child,
                    )
                    or call_name
                )

        for keyword in decorator.keywords:
            if keyword.arg != "dependencies":
                continue

            for child in ast.walk(
                keyword.value,
            ):
                if not isinstance(
                    child,
                    ast.Call,
                ):
                    continue

                call_name = self._call_name(
                    child.func,
                )

                if call_name.endswith(
                    (
                        "Depends",
                        "Security",
                    ),
                ):
                    dependencies.append(
                        self._node_text(
                            child,
                        )
                        or call_name
                    )

        return dependencies

    @staticmethod
    def _has_auth_dependency(
        endpoint: FastAPIEndpoint,
    ) -> bool:
        for dependency in endpoint.dependencies:
            lowered = dependency.lower()

            if any(
                marker in lowered
                for marker in (
                    FastAPIEndpointSecurityAnalyzer
                    .AUTH_DEPENDENCY_PARTS
                )
            ):
                return True

        return False

    @staticmethod
    def _is_sensitive_endpoint(
        endpoint: FastAPIEndpoint,
    ) -> bool:
        combined = (
            f"{endpoint.path} "
            f"{endpoint.function_name}"
        ).lower()

        return any(
            part in combined
            for part in (
                FastAPIEndpointSecurityAnalyzer
                .SENSITIVE_PATH_PARTS
            )
        )

    def _contains_exception_text(
        self,
        node: ast.AST,
        exception_names: set[str],
    ) -> bool:
        if isinstance(
            node,
            ast.Call,
        ):
            call_name = self._call_name(
                node.func,
            )

            if call_name == "str" and node.args:
                argument = node.args[0]

                return (
                    isinstance(
                        argument,
                        ast.Name,
                    )
                    and argument.id in exception_names
                )

        if isinstance(
            node,
            ast.Name,
        ):
            return node.id in exception_names

        return False

    def _add_issue(
        self,
        *,
        rule: FastAPIEndpointRule,
        endpoint: FastAPIEndpoint,
        node: ast.AST,
    ) -> None:
        self.issues.append(
            SourceIssue(
                rule_id=rule.rule_id,
                title=rule.title,
                description=rule.description,
                category=rule.category,
                severity=rule.severity,
                confidence=rule.confidence,
                remediation=rule.remediation,
                location=SourceLocation(
                    file_path=self.source_file.relative_path,
                    line_start=getattr(
                        node,
                        "lineno",
                        None,
                    ),
                    line_end=getattr(
                        node,
                        "end_lineno",
                        None,
                    ),
                    column_start=self._column_number(
                        node,
                        "col_offset",
                    ),
                    column_end=self._column_number(
                        node,
                        "end_col_offset",
                    ),
                    function_name=endpoint.function_name,
                    class_name=(
                        self._class_stack[-1]
                        if self._class_stack
                        else None
                    ),
                ),
                evidence=self._node_text(
                    node,
                ),
                cwe_id=rule.cwe_id,
                owasp_reference=rule.owasp_reference,
                metadata={
                    "analyzer": (
                        FastAPIEndpointSecurityAnalyzer
                        .name
                    ),
                    "framework": "fastapi",
                    "language": "python",
                    "endpoint_method": endpoint.method,
                    "endpoint_path": endpoint.path,
                    **rule.metadata,
                },
            ),
        )

    @staticmethod
    def _endpoint_path(
        decorator: ast.Call,
    ) -> str:
        if not decorator.args:
            return "/"

        value = decorator.args[0]

        if (
            isinstance(
                value,
                ast.Constant,
            )
            and isinstance(
                value.value,
                str,
            )
        ):
            return value.value

        return "<dynamic>"

    @classmethod
    def _call_name(
        cls,
        node: ast.AST,
    ) -> str:
        if isinstance(
            node,
            ast.Name,
        ):
            return node.id

        if isinstance(
            node,
            ast.Attribute,
        ):
            parent = cls._call_name(
                node.value,
            )

            if parent:
                return (
                    f"{parent}.{node.attr}"
                )

            return node.attr

        return ""

    def _node_text(
        self,
        node: ast.AST | None,
    ) -> str | None:
        if node is None:
            return None

        segment = ast.get_source_segment(
            self.source_file.content,
            node,
        )

        if segment is None:
            try:
                segment = ast.unparse(
                    node,
                )
            except Exception:
                return None

        return " ".join(
            segment.strip().split(),
        )[:500]

    @staticmethod
    def _column_number(
        node: ast.AST,
        attribute: str,
    ) -> int | None:
        value = getattr(
            node,
            attribute,
            None,
        )

        if value is None:
            return None

        return int(
            value,
        ) + 1
