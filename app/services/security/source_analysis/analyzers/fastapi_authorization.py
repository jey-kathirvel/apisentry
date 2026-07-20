from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Any

from app.services.security.source_analysis.base import SourceAnalyzer
from app.services.security.source_analysis.context import SourceAnalysisContext
from app.services.security.source_analysis.models import (
    SourceAnalysisResult,
    SourceFile,
    SourceIssue,
    SourceIssueConfidence,
    SourceIssueSeverity,
    SourceLocation,
)


@dataclass(slots=True, frozen=True)
class AuthorizationRule:
    rule_id: str
    title: str
    description: str
    category: str
    severity: SourceIssueSeverity
    confidence: SourceIssueConfidence
    remediation: str
    cwe_id: str
    owasp_reference: str


class FastAPIAuthorizationSecurityAnalyzer(SourceAnalyzer):
    name = "fastapi-authorization-security"

    languages = ("python",)
    frameworks = ("fastapi",)
    priority = 91

    IDOR_RULE = AuthorizationRule(
        rule_id="FASTAPI-AUTH-003",
        title="Potential broken object-level authorization",
        description=(
            "The endpoint accesses an object using a request path identifier "
            "without a visible ownership or object-level authorization check."
        ),
        category="authorization",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.MEDIUM,
        remediation=(
            "Verify that the authenticated principal owns the requested object "
            "or has explicit permission to access it before returning it."
        ),
        cwe_id="CWE-639",
        owasp_reference="API1:2023",
    )

    USER_CONTROLLED_AUTH_RULE = AuthorizationRule(
        rule_id="FASTAPI-AUTH-008",
        title="Authorization decision uses request-controlled privilege",
        description=(
            "A role, permission, administrator flag, or privilege value from "
            "request-controlled input is used in an authorization decision."
        ),
        category="authorization",
        severity=SourceIssueSeverity.HIGH,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Make authorization decisions using the authenticated principal "
            "and trusted server-side roles or permissions."
        ),
        cwe_id="CWE-807",
        owasp_reference="API5:2023",
    )

    MISSING_OWNERSHIP_RULE = AuthorizationRule(
        rule_id="FASTAPI-AUTH-009",
        title="Missing ownership validation before object modification",
        description=(
            "The endpoint updates or deletes an object selected using a request "
            "identifier without a visible ownership or authorization check."
        ),
        category="authorization",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.MEDIUM,
        remediation=(
            "Validate ownership or explicit authorization before updating or "
            "deleting the object."
        ),
        cwe_id="CWE-862",
        owasp_reference="API1:2023",
    )

    HTTP_METHODS = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
    }

    MUTATING_METHODS = {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }

    REQUEST_OBJECT_NAMES = {
        "request",
        "payload",
        "body",
        "data",
        "form",
        "input",
        "schema",
        "command",
    }

    PRIVILEGE_FIELDS = {
        "role",
        "roles",
        "permission",
        "permissions",
        "privilege",
        "privileges",
        "is_admin",
        "admin",
        "is_staff",
        "is_superuser",
        "access_level",
    }

    TRUSTED_PRINCIPAL_MARKERS = {
        "current_user",
        "authenticated_user",
        "principal",
        "session_user",
        "request_user",
    }

    AUTHORIZATION_HELPERS = {
        "authorize",
        "authorize_object",
        "check_access",
        "check_authorization",
        "check_permission",
        "enforce_permission",
        "has_access",
        "has_permission",
        "is_admin",
        "require_admin",
        "require_owner",
        "require_permission",
        "verify_access",
        "verify_authorization",
        "verify_ownership",
    }

    OWNERSHIP_FIELDS = {
        "owner",
        "owner_id",
        "user",
        "user_id",
        "created_by",
        "created_by_id",
        "account_id",
        "tenant_id",
        "organization_id",
    }

    OBJECT_ACCESS_METHODS = {
        "get",
        "first",
        "one",
        "one_or_none",
        "scalar",
        "scalar_one",
        "scalar_one_or_none",
        "execute",
        "filter",
        "filter_by",
        "where",
    }

    MUTATION_METHODS = {
        "delete",
        "update",
        "merge",
        "commit",
        "flush",
        "save",
        "remove",
    }

    AUTH_DEPENDENCY_MARKERS = {
        "auth",
        "current_user",
        "get_current",
        "jwt",
        "oauth",
        "principal",
        "security",
        "session_user",
        "token",
    }

    ADMIN_DEPENDENCY_MARKERS = {
        "admin",
        "administrator",
        "permission",
        "require_role",
        "require_permission",
        "superuser",
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
        authorization_checks = 0
        ownership_checks = 0
        idor_candidates = 0

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

            visitor = _FastAPIAuthorizationVisitor(
                source_file=source_file,
            )
            visitor.visit(tree)

            issues.extend(visitor.issues)
            endpoints_scanned += visitor.endpoints_scanned
            authorization_checks += visitor.authorization_checks
            ownership_checks += visitor.ownership_checks
            idor_candidates += visitor.idor_candidates

        result = SourceAnalysisResult(
            analyzer=self.name,
            files_scanned=files_scanned,
            issues=issues,
            errors=errors,
            metadata={
                "engine": "python-ast",
                "framework": "fastapi",
                "endpoints_scanned": endpoints_scanned,
                "authorization_checks": authorization_checks,
                "ownership_checks": ownership_checks,
                "idor_candidates": idor_candidates,
                "rule_ids": [
                    "FASTAPI-AUTH-003",
                    "FASTAPI-AUTH-008",
                    "FASTAPI-AUTH-009",
                ],
            },
        )

        result.deduplicate()
        return result


class _FastAPIAuthorizationVisitor(ast.NodeVisitor):
    def __init__(
        self,
        *,
        source_file: SourceFile,
    ) -> None:
        self.source_file = source_file
        self.issues: list[SourceIssue] = []

        self.endpoints_scanned = 0
        self.authorization_checks = 0
        self.ownership_checks = 0
        self.idor_candidates = 0

        self._class_stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._inspect_function(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._inspect_function(node)
        return node

    def _inspect_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        endpoint_decorators = [
            decorator
            for decorator in node.decorator_list
            if self._is_endpoint_decorator(decorator)
        ]

        if not endpoint_decorators:
            self.generic_visit(node)
            return

        self.endpoints_scanned += len(endpoint_decorators)

        request_auth_issues = self._find_request_controlled_auth(node)

        for comparison_node, field_name in request_auth_issues:
            self._add_issue(
                rule=FastAPIAuthorizationSecurityAnalyzer.USER_CONTROLLED_AUTH_RULE,
                node=comparison_node,
                function_name=node.name,
                metadata={
                    "privileged_field": field_name,
                },
            )

        has_authz_check = self._has_authorization_check(node)
        has_ownership_check = self._has_ownership_check(node)

        if has_authz_check:
            self.authorization_checks += 1

        if has_ownership_check:
            self.ownership_checks += 1

        dependencies = self._collect_dependencies(
            node=node,
            decorators=endpoint_decorators,
        )

        has_admin_dependency = self._has_admin_dependency(dependencies)

        for decorator in endpoint_decorators:
            method = self._endpoint_method(decorator)
            path = self._endpoint_path(decorator)
            path_parameters = self._path_parameters(path)

            if not path_parameters:
                continue

            used_identifiers = {
                parameter
                for parameter in path_parameters
                if self._identifier_used_for_object_access(
                    node=node,
                    identifier=parameter,
                )
            }

            if not used_identifiers:
                continue

            if has_admin_dependency or has_authz_check or has_ownership_check:
                continue

            self.idor_candidates += 1

            if method == "GET":
                self._add_issue(
                    rule=FastAPIAuthorizationSecurityAnalyzer.IDOR_RULE,
                    node=decorator,
                    function_name=node.name,
                    metadata={
                        "endpoint_method": method,
                        "endpoint_path": path,
                        "object_identifiers": sorted(used_identifiers),
                    },
                )

            if (
                method
                in FastAPIAuthorizationSecurityAnalyzer.MUTATING_METHODS
                and self._contains_object_mutation(node)
            ):
                self._add_issue(
                    rule=(
                        FastAPIAuthorizationSecurityAnalyzer
                        .MISSING_OWNERSHIP_RULE
                    ),
                    node=decorator,
                    function_name=node.name,
                    metadata={
                        "endpoint_method": method,
                        "endpoint_path": path,
                        "object_identifiers": sorted(used_identifiers),
                    },
                )

    def _find_request_controlled_auth(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[tuple[ast.AST, str]]:
        findings: list[tuple[ast.AST, str]] = []

        for child in ast.walk(node):
            candidate_nodes: list[ast.AST] = []

            if isinstance(child, ast.If):
                candidate_nodes.append(child.test)

            elif isinstance(child, ast.IfExp):
                candidate_nodes.append(child.test)

            elif isinstance(child, ast.Assert):
                candidate_nodes.append(child.test)

            for candidate in candidate_nodes:
                for nested in ast.walk(candidate):
                    field_name = self._request_privilege_field(nested)

                    if field_name:
                        findings.append(
                            (
                                candidate,
                                field_name,
                            )
                        )
                        break

        return findings

    @classmethod
    def _request_privilege_field(
        cls,
        node: ast.AST,
    ) -> str:
        if isinstance(node, ast.Attribute):
            root = cls._root_name(node)

            if (
                root
                in FastAPIAuthorizationSecurityAnalyzer.REQUEST_OBJECT_NAMES
                and node.attr.lower()
                in FastAPIAuthorizationSecurityAnalyzer.PRIVILEGE_FIELDS
            ):
                return node.attr.lower()

        if isinstance(node, ast.Subscript):
            root = cls._root_name(node.value)
            key = cls._subscript_key(node)

            if (
                root
                in FastAPIAuthorizationSecurityAnalyzer.REQUEST_OBJECT_NAMES
                and key
                in FastAPIAuthorizationSecurityAnalyzer.PRIVILEGE_FIELDS
            ):
                return key

        return ""

    @classmethod
    def _has_authorization_check(
        cls,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue

            call_name = cls._call_name(child.func).lower()
            leaf_name = call_name.rsplit(".", 1)[-1]

            if (
                leaf_name
                in FastAPIAuthorizationSecurityAnalyzer.AUTHORIZATION_HELPERS
            ):
                return True

        return False

    @classmethod
    def _has_ownership_check(
        cls,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        for child in ast.walk(node):
            if not isinstance(child, ast.Compare):
                continue

            names = {
                cls._expression_name(item).lower()
                for item in [
                    child.left,
                    *child.comparators,
                ]
            }

            names.discard("")

            has_ownership_field = any(
                name.rsplit(".", 1)[-1]
                in FastAPIAuthorizationSecurityAnalyzer.OWNERSHIP_FIELDS
                for name in names
            )

            has_trusted_principal = any(
                any(
                    marker in name
                    for marker in (
                        FastAPIAuthorizationSecurityAnalyzer
                        .TRUSTED_PRINCIPAL_MARKERS
                    )
                )
                for name in names
            )

            if has_ownership_field and has_trusted_principal:
                return True

        return False

    @classmethod
    def _identifier_used_for_object_access(
        cls,
        *,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        identifier: str,
    ) -> bool:
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue

            call_name = cls._call_name(child.func).lower()
            leaf_name = call_name.rsplit(".", 1)[-1]

            if (
                leaf_name
                not in FastAPIAuthorizationSecurityAnalyzer
                .OBJECT_ACCESS_METHODS
            ):
                continue

            for argument in [
                *child.args,
                *[
                    keyword.value
                    for keyword in child.keywords
                ],
            ]:
                if cls._contains_name(
                    argument,
                    identifier,
                ):
                    return True

        return False

    @classmethod
    def _contains_object_mutation(
        cls,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = cls._call_name(child.func).lower()
                leaf_name = call_name.rsplit(".", 1)[-1]

                if (
                    leaf_name
                    in FastAPIAuthorizationSecurityAnalyzer.MUTATION_METHODS
                ):
                    return True

            if isinstance(
                child,
                (
                    ast.Assign,
                    ast.AnnAssign,
                    ast.AugAssign,
                ),
            ):
                return True

        return False

    @classmethod
    def _collect_dependencies(
        cls,
        *,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        decorators: list[ast.Call],
    ) -> list[str]:
        dependencies: list[str] = []

        for child in ast.walk(node.args):
            if not isinstance(child, ast.Call):
                continue

            call_name = cls._call_name(child.func)

            if call_name.endswith(("Depends", "Security")):
                dependencies.append(ast.unparse(child))

        for decorator in decorators:
            for keyword in decorator.keywords:
                if keyword.arg != "dependencies":
                    continue

                for child in ast.walk(keyword.value):
                    if not isinstance(child, ast.Call):
                        continue

                    call_name = cls._call_name(child.func)

                    if call_name.endswith(("Depends", "Security")):
                        dependencies.append(ast.unparse(child))

        return dependencies

    @staticmethod
    def _has_admin_dependency(
        dependencies: list[str],
    ) -> bool:
        for dependency in dependencies:
            lowered = dependency.lower()

            if any(
                marker in lowered
                for marker in (
                    FastAPIAuthorizationSecurityAnalyzer
                    .ADMIN_DEPENDENCY_MARKERS
                )
            ):
                return True

        return False

    @classmethod
    def _is_endpoint_decorator(
        cls,
        decorator: ast.AST,
    ) -> bool:
        if not isinstance(decorator, ast.Call):
            return False

        method = cls._call_name(
            decorator.func,
        ).rsplit(".", 1)[-1].lower()

        return (
            method
            in FastAPIAuthorizationSecurityAnalyzer.HTTP_METHODS
        )

    @classmethod
    def _endpoint_method(
        cls,
        decorator: ast.Call,
    ) -> str:
        return cls._call_name(
            decorator.func,
        ).rsplit(".", 1)[-1].upper()

    @staticmethod
    def _endpoint_path(
        decorator: ast.Call,
    ) -> str:
        if not decorator.args:
            return "/"

        first_argument = decorator.args[0]

        if (
            isinstance(first_argument, ast.Constant)
            and isinstance(first_argument.value, str)
        ):
            return first_argument.value

        return "<dynamic>"

    @staticmethod
    def _path_parameters(path: str) -> set[str]:
        return set(
            re.findall(
                r"\{([A-Za-z_][A-Za-z0-9_]*)",
                path,
            )
        )

    @classmethod
    def _contains_name(
        cls,
        node: ast.AST,
        identifier: str,
    ) -> bool:
        return any(
            isinstance(child, ast.Name)
            and child.id == identifier
            for child in ast.walk(node)
        )

    @classmethod
    def _expression_name(
        cls,
        node: ast.AST,
    ) -> str:
        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            parent = cls._expression_name(node.value)

            return (
                f"{parent}.{node.attr}"
                if parent
                else node.attr
            )

        if isinstance(node, ast.Subscript):
            parent = cls._expression_name(node.value)
            key = cls._subscript_key(node)

            return (
                f"{parent}.{key}"
                if parent and key
                else parent
            )

        return ""

    @classmethod
    def _call_name(
        cls,
        node: ast.AST,
    ) -> str:
        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            parent = cls._call_name(node.value)

            return (
                f"{parent}.{node.attr}"
                if parent
                else node.attr
            )

        return ""

    @classmethod
    def _root_name(
        cls,
        node: ast.AST,
    ) -> str:
        current = node

        while isinstance(
            current,
            (
                ast.Attribute,
                ast.Subscript,
            ),
        ):
            if isinstance(current, ast.Attribute):
                current = current.value
            else:
                current = current.value

        if isinstance(current, ast.Name):
            return current.id.lower()

        return ""

    @staticmethod
    def _subscript_key(
        node: ast.Subscript,
    ) -> str:
        if (
            isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            return node.slice.value.lower()

        return ""

    def _add_issue(
        self,
        *,
        rule: AuthorizationRule,
        node: ast.AST,
        function_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        evidence = ast.get_source_segment(
            self.source_file.content,
            node,
        )

        if evidence is None:
            try:
                evidence = ast.unparse(node)
            except Exception:
                evidence = None

        if evidence is not None:
            evidence = " ".join(
                evidence.strip().split()
            )[:500]

        issue_metadata: dict[str, Any] = {
            "analyzer": FastAPIAuthorizationSecurityAnalyzer.name,
            "framework": "fastapi",
            "language": "python",
        }

        if metadata:
            issue_metadata.update(metadata)

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
                    line_start=getattr(node, "lineno", None),
                    line_end=getattr(node, "end_lineno", None),
                    column_start=self._column(
                        node,
                        "col_offset",
                    ),
                    column_end=self._column(
                        node,
                        "end_col_offset",
                    ),
                    function_name=function_name,
                    class_name=(
                        self._class_stack[-1]
                        if self._class_stack
                        else None
                    ),
                ),
                evidence=evidence,
                cwe_id=rule.cwe_id,
                owasp_reference=rule.owasp_reference,
                metadata=issue_metadata,
            )
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

        return int(value) + 1
