from __future__ import annotations

import ast
from dataclasses import dataclass
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
class AuthenticationRule:
    rule_id: str
    title: str
    description: str
    category: str
    severity: SourceIssueSeverity
    confidence: SourceIssueConfidence
    remediation: str
    cwe_id: str
    owasp_reference: str


class FastAPIAuthenticationSecurityAnalyzer(
    SourceAnalyzer,
):
    name = "fastapi-authentication-security"

    languages = (
        "python",
    )

    frameworks = (
        "fastapi",
    )

    priority = 90

    JWT_AUDIENCE_RULE = AuthenticationRule(
        rule_id="FASTAPI-AUTH-004",
        title="JWT decoded without audience validation",
        description=(
            "A JWT token is decoded without validating its intended "
            "audience. A token issued for another service may therefore "
            "be accepted by this API."
        ),
        category="authentication",
        severity=SourceIssueSeverity.HIGH,
        confidence=SourceIssueConfidence.MEDIUM,
        remediation=(
            "Provide the expected audience when decoding the JWT and "
            "require the aud claim."
        ),
        cwe_id="CWE-287",
        owasp_reference="API2:2023",
    )

    JWT_ISSUER_RULE = AuthenticationRule(
        rule_id="FASTAPI-AUTH-005",
        title="JWT decoded without issuer validation",
        description=(
            "A JWT token is decoded without validating the trusted issuer."
        ),
        category="authentication",
        severity=SourceIssueSeverity.HIGH,
        confidence=SourceIssueConfidence.MEDIUM,
        remediation=(
            "Provide the expected issuer when decoding the JWT and "
            "require the iss claim."
        ),
        cwe_id="CWE-287",
        owasp_reference="API2:2023",
    )

    JWT_SIGNATURE_RULE = AuthenticationRule(
        rule_id="FASTAPI-AUTH-006",
        title="JWT signature verification disabled",
        description=(
            "JWT decoding explicitly disables signature verification, "
            "allowing forged tokens to be accepted."
        ),
        category="authentication",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Never disable JWT signature verification. Restrict accepted "
            "algorithms and validate the token using the correct signing key."
        ),
        cwe_id="CWE-347",
        owasp_reference="API2:2023",
    )

    ANONYMOUS_ADMIN_RULE = AuthenticationRule(
        rule_id="FASTAPI-AUTH-007",
        title="Anonymous administrative endpoint",
        description=(
            "An administrative FastAPI endpoint does not declare a visible "
            "authentication or authorization dependency."
        ),
        category="authorization",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Require an authenticated principal and enforce an administrator "
            "permission or role dependency before executing this endpoint."
        ),
        cwe_id="CWE-862",
        owasp_reference="API5:2023",
    )

    ROLE_ASSIGNMENT_RULE = AuthenticationRule(
        rule_id="FASTAPI-AUTH-010",
        title="Privilege assignment from request-controlled input",
        description=(
            "A role, permission, administrator flag, or privilege field "
            "appears to be assigned directly from request-controlled input."
        ),
        category="authorization",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Do not accept privileged account fields from normal request "
            "payloads. Assign roles and permissions only through a dedicated "
            "administrator-authorized workflow."
        ),
        cwe_id="CWE-269",
        owasp_reference="API5:2023",
    )

    ADMIN_MARKERS = {
        "admin",
        "administrator",
        "superuser",
        "system",
        "management",
        "roles",
        "permissions",
    }

    AUTH_MARKERS = {
        "auth",
        "authorize",
        "current_user",
        "get_current",
        "jwt",
        "permission",
        "principal",
        "require_",
        "role",
        "security",
        "session_user",
        "token",
    }

    PRIVILEGE_FIELDS = {
        "admin",
        "is_admin",
        "is_staff",
        "is_superuser",
        "permission",
        "permissions",
        "privilege",
        "privileges",
        "role",
        "roles",
    }

    REQUEST_OBJECT_NAMES = {
        "body",
        "data",
        "form",
        "input",
        "payload",
        "request",
        "schema",
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
        context: SourceAnalysisContext,
        source_file: SourceFile | None = None,
    ) -> bool:
        return super().supports(
            context=context,
            source_file=source_file,
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
        endpoints_scanned = 0
        jwt_decode_calls = 0

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
                    (
                        f"{source_file.relative_path}:"
                        f"{exc.lineno or 0}: SyntaxError: "
                        f"{exc.msg or 'invalid syntax'}"
                    )
                )
                continue

            visitor = _FastAPIAuthenticationVisitor(
                source_file=source_file,
            )

            visitor.visit(
                tree,
            )

            issues.extend(
                visitor.issues,
            )

            endpoints_scanned += (
                visitor.endpoints_scanned
            )

            jwt_decode_calls += (
                visitor.jwt_decode_calls
            )

        result = SourceAnalysisResult(
            analyzer=self.name,
            files_scanned=files_scanned,
            issues=issues,
            errors=errors,
            metadata={
                "engine": "python-ast",
                "framework": "fastapi",
                "endpoints_scanned": endpoints_scanned,
                "jwt_decode_calls": jwt_decode_calls,
                "rule_ids": [
                    "FASTAPI-AUTH-004",
                    "FASTAPI-AUTH-005",
                    "FASTAPI-AUTH-006",
                    "FASTAPI-AUTH-007",
                    "FASTAPI-AUTH-010",
                ],
            },
        )

        result.deduplicate()

        return result


class _FastAPIAuthenticationVisitor(
    ast.NodeVisitor,
):
    def __init__(
        self,
        *,
        source_file: SourceFile,
    ) -> None:
        self.source_file = source_file
        self.issues: list[SourceIssue] = []
        self.endpoints_scanned = 0
        self.jwt_decode_calls = 0
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []

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
        self._visit_function(
            node,
        )

        return node

    def visit_AsyncFunctionDef(
        self,
        node: ast.AsyncFunctionDef,
    ) -> Any:
        self._visit_function(
            node,
        )

        return node

    def visit_Call(
        self,
        node: ast.Call,
    ) -> Any:
        if self._is_jwt_decode_call(
            node,
        ):
            self.jwt_decode_calls += 1

            self._inspect_jwt_decode(
                node,
            )

        self.generic_visit(
            node,
        )

        return node

    def visit_Assign(
        self,
        node: ast.Assign,
    ) -> Any:
        for target in node.targets:
            self._inspect_privilege_assignment(
                target=target,
                value=node.value,
                node=node,
            )

        self.generic_visit(
            node,
        )

        return node

    def visit_AnnAssign(
        self,
        node: ast.AnnAssign,
    ) -> Any:
        if node.value is not None:
            self._inspect_privilege_assignment(
                target=node.target,
                value=node.value,
                node=node,
            )

        self.generic_visit(
            node,
        )

        return node

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        self._function_stack.append(
            node.name,
        )

        endpoint_decorators = [
            decorator
            for decorator in node.decorator_list
            if self._is_endpoint_decorator(
                decorator,
            )
        ]

        if endpoint_decorators:
            self.endpoints_scanned += len(
                endpoint_decorators,
            )

            for decorator in endpoint_decorators:
                self._inspect_admin_endpoint(
                    node=node,
                    decorator=decorator,
                )

        for child in node.body:
            self.visit(
                child,
            )

        self._function_stack.pop()

    def _inspect_jwt_decode(
        self,
        node: ast.Call,
    ) -> None:
        options_node = self._keyword_value(
            node,
            "options",
        )

        audience_node = self._keyword_value(
            node,
            "audience",
        )

        issuer_node = self._keyword_value(
            node,
            "issuer",
        )

        if self._dict_boolean_value(
            options_node,
            "verify_signature",
        ) is False:
            self._add_issue(
                rule=(
                    FastAPIAuthenticationSecurityAnalyzer
                    .JWT_SIGNATURE_RULE
                ),
                node=node,
                metadata={
                    "jwt_check": "signature",
                },
            )

        verify_audience = self._dict_boolean_value(
            options_node,
            "verify_aud",
        )

        if (
            audience_node is None
            and verify_audience is not False
        ):
            self._add_issue(
                rule=(
                    FastAPIAuthenticationSecurityAnalyzer
                    .JWT_AUDIENCE_RULE
                ),
                node=node,
                metadata={
                    "jwt_check": "audience",
                },
            )

        verify_issuer = self._dict_boolean_value(
            options_node,
            "verify_iss",
        )

        if (
            issuer_node is None
            and verify_issuer is not False
        ):
            self._add_issue(
                rule=(
                    FastAPIAuthenticationSecurityAnalyzer
                    .JWT_ISSUER_RULE
                ),
                node=node,
                metadata={
                    "jwt_check": "issuer",
                },
            )

    def _inspect_admin_endpoint(
        self,
        *,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        decorator: ast.Call,
    ) -> None:
        endpoint_path = self._endpoint_path(
            decorator,
        )

        combined = (
            f"{endpoint_path} {node.name}"
        ).lower()

        if not any(
            marker in combined
            for marker in (
                FastAPIAuthenticationSecurityAnalyzer
                .ADMIN_MARKERS
            )
        ):
            return

        dependencies = self._collect_dependencies(
            node=node,
            decorator=decorator,
        )

        if self._has_auth_dependency(
            dependencies,
        ):
            return

        self._add_issue(
            rule=(
                FastAPIAuthenticationSecurityAnalyzer
                .ANONYMOUS_ADMIN_RULE
            ),
            node=decorator,
            metadata={
                "endpoint_method": (
                    self._endpoint_method(
                        decorator,
                    )
                ),
                "endpoint_path": endpoint_path,
            },
        )

    def _inspect_privilege_assignment(
        self,
        *,
        target: ast.AST,
        value: ast.AST,
        node: ast.AST,
    ) -> None:
        target_field = self._assignment_field(
            target,
        )

        if (
            target_field
            not in (
                FastAPIAuthenticationSecurityAnalyzer
                .PRIVILEGE_FIELDS
            )
        ):
            return

        if not self._is_request_controlled(
            value,
        ):
            return

        self._add_issue(
            rule=(
                FastAPIAuthenticationSecurityAnalyzer
                .ROLE_ASSIGNMENT_RULE
            ),
            node=node,
            metadata={
                "privileged_field": target_field,
            },
        )

    @classmethod
    def _is_request_controlled(
        cls,
        node: ast.AST,
    ) -> bool:
        if isinstance(
            node,
            ast.Attribute,
        ):
            root_name = cls._root_name(
                node,
            )

            return (
                root_name
                in (
                    FastAPIAuthenticationSecurityAnalyzer
                    .REQUEST_OBJECT_NAMES
                )
            )

        if isinstance(
            node,
            ast.Subscript,
        ):
            root_name = cls._root_name(
                node.value,
            )

            return (
                root_name
                in (
                    FastAPIAuthenticationSecurityAnalyzer
                    .REQUEST_OBJECT_NAMES
                )
            )

        if isinstance(
            node,
            ast.Call,
        ):
            call_name = cls._call_name(
                node.func,
            ).lower()

            if any(
                marker in call_name
                for marker in {
                    "dict",
                    "json",
                    "model_dump",
                    "form",
                    "body",
                }
            ):
                return True

        return False

    @staticmethod
    def _assignment_field(
        node: ast.AST,
    ) -> str:
        if isinstance(
            node,
            ast.Attribute,
        ):
            return node.attr.lower()

        if isinstance(
            node,
            ast.Name,
        ):
            return node.id.lower()

        if isinstance(
            node,
            ast.Subscript,
        ):
            key = node.slice

            if (
                isinstance(
                    key,
                    ast.Constant,
                )
                and isinstance(
                    key.value,
                    str,
                )
            ):
                return key.value.lower()

        return ""

    @classmethod
    def _is_jwt_decode_call(
        cls,
        node: ast.Call,
    ) -> bool:
        call_name = cls._call_name(
            node.func,
        ).lower()

        return (
            call_name == "decode"
            or call_name.endswith(
                ".decode",
            )
        ) and (
            "jwt" in call_name
            or cls._looks_like_jwt_decode(
                node,
            )
        )

    @staticmethod
    def _looks_like_jwt_decode(
        node: ast.Call,
    ) -> bool:
        keyword_names = {
            keyword.arg
            for keyword in node.keywords
            if keyword.arg is not None
        }

        return bool(
            {
                "algorithms",
                "audience",
                "issuer",
                "options",
            }
            & keyword_names
        )

    @staticmethod
    def _keyword_value(
        node: ast.Call,
        name: str,
    ) -> ast.AST | None:
        for keyword in node.keywords:
            if keyword.arg == name:
                return keyword.value

        return None

    @staticmethod
    def _dict_boolean_value(
        node: ast.AST | None,
        key_name: str,
    ) -> bool | None:
        if not isinstance(
            node,
            ast.Dict,
        ):
            return None

        for key, value in zip(
            node.keys,
            node.values,
            strict=False,
        ):
            if not (
                isinstance(
                    key,
                    ast.Constant,
                )
                and key.value == key_name
            ):
                continue

            if (
                isinstance(
                    value,
                    ast.Constant,
                )
                and isinstance(
                    value.value,
                    bool,
                )
            ):
                return value.value

        return None

    @classmethod
    def _collect_dependencies(
        cls,
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

            call_name = cls._call_name(
                child.func,
            )

            if call_name.endswith(
                (
                    "Depends",
                    "Security",
                ),
            ):
                dependencies.append(
                    ast.unparse(
                        child,
                    )
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

                call_name = cls._call_name(
                    child.func,
                )

                if call_name.endswith(
                    (
                        "Depends",
                        "Security",
                    ),
                ):
                    dependencies.append(
                        ast.unparse(
                            child,
                        )
                    )

        return dependencies

    @staticmethod
    def _has_auth_dependency(
        dependencies: list[str],
    ) -> bool:
        for dependency in dependencies:
            lowered = dependency.lower()

            if any(
                marker in lowered
                for marker in (
                    FastAPIAuthenticationSecurityAnalyzer
                    .AUTH_MARKERS
                )
            ):
                return True

        return False

    @classmethod
    def _is_endpoint_decorator(
        cls,
        decorator: ast.AST,
    ) -> bool:
        if not isinstance(
            decorator,
            ast.Call,
        ):
            return False

        method = cls._call_name(
            decorator.func,
        ).rsplit(
            ".",
            1,
        )[-1].lower()

        return (
            method
            in (
                FastAPIAuthenticationSecurityAnalyzer
                .HTTP_METHODS
            )
        )

    @classmethod
    def _endpoint_method(
        cls,
        decorator: ast.Call,
    ) -> str:
        return cls._call_name(
            decorator.func,
        ).rsplit(
            ".",
            1,
        )[-1].upper()

    @staticmethod
    def _endpoint_path(
        decorator: ast.Call,
    ) -> str:
        if not decorator.args:
            return "/"

        first_argument = decorator.args[0]

        if (
            isinstance(
                first_argument,
                ast.Constant,
            )
            and isinstance(
                first_argument.value,
                str,
            )
        ):
            return first_argument.value

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

    @classmethod
    def _root_name(
        cls,
        node: ast.AST,
    ) -> str:
        current = node

        while isinstance(
            current,
            ast.Attribute,
        ):
            current = current.value

        if isinstance(
            current,
            ast.Name,
        ):
            return current.id.lower()

        return ""

    def _add_issue(
        self,
        *,
        rule: AuthenticationRule,
        node: ast.AST,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        evidence = ast.get_source_segment(
            self.source_file.content,
            node,
        )

        if evidence is None:
            try:
                evidence = ast.unparse(
                    node,
                )
            except Exception:
                evidence = None

        if evidence is not None:
            evidence = " ".join(
                evidence.strip().split(),
            )[:500]

        issue_metadata = {
            "analyzer": (
                FastAPIAuthenticationSecurityAnalyzer
                .name
            ),
            "framework": "fastapi",
            "language": "python",
        }

        if metadata:
            issue_metadata.update(
                metadata,
            )

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
                    column_start=self._column(
                        node,
                        "col_offset",
                    ),
                    column_end=self._column(
                        node,
                        "end_col_offset",
                    ),
                    function_name=(
                        self._function_stack[-1]
                        if self._function_stack
                        else None
                    ),
                    class_name=(
                        self._class_stack[-1]
                        if self._class_stack
                        else None
                    ),
                ),
                evidence=evidence,
                cwe_id=rule.cwe_id,
                owasp_reference=(
                    rule.owasp_reference
                ),
                metadata=issue_metadata,
            ),
        )

    @staticmethod
    def _column(
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
