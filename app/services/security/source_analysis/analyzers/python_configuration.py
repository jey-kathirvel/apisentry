from __future__ import annotations

import ast
import math
import re
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
class PythonConfigurationRule:
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


class PythonConfigurationSecurityAnalyzer(
    SourceAnalyzer,
):
    name = "python-configuration-security"

    languages = (
        "python",
    )

    priority = 90

    HARDCODED_SECRET_RULE = PythonConfigurationRule(
        rule_id="SECRET-001",
        title="Hardcoded secret detected",
        description=(
            "A sensitive credential or secret appears to be "
            "hardcoded directly in Python source code."
        ),
        category="secrets-management",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Remove the secret from source control, rotate the "
            "credential immediately, and load it from a protected "
            "environment variable or secrets-management service."
        ),
        cwe_id="CWE-798",
        owasp_reference="API8:2023",
    )

    WEAK_SECRET_RULE = PythonConfigurationRule(
        rule_id="SECRET-002",
        title="Weak application secret detected",
        description=(
            "A security-sensitive secret appears too short, "
            "predictable, or low entropy for cryptographic use."
        ),
        category="secrets-management",
        severity=SourceIssueSeverity.HIGH,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Generate a cryptographically random secret of at least "
            "32 bytes and store it outside the source repository."
        ),
        cwe_id="CWE-330",
        owasp_reference="API2:2023",
    )

    DEBUG_RULE = PythonConfigurationRule(
        rule_id="CONFIG-001",
        title="Debug mode enabled",
        description=(
            "Debug mode is enabled in application configuration. "
            "Production debug output may expose sensitive internal "
            "details or interactive debugging capabilities."
        ),
        category="security-misconfiguration",
        severity=SourceIssueSeverity.HIGH,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Disable debug mode in production and control diagnostic "
            "logging through environment-specific configuration."
        ),
        cwe_id="CWE-489",
        owasp_reference="API8:2023",
    )

    VERIFY_DISABLED_RULE = PythonConfigurationRule(
        rule_id="TLS-001",
        title="TLS certificate verification disabled",
        description=(
            "An outbound HTTP request explicitly disables TLS "
            "certificate verification, allowing man-in-the-middle "
            "attacks."
        ),
        category="transport-security",
        severity=SourceIssueSeverity.HIGH,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Enable certificate verification. Configure the correct "
            "trusted CA bundle instead of using verify=False."
        ),
        cwe_id="CWE-295",
        owasp_reference="API8:2023",
    )

    JWT_NONE_RULE = PythonConfigurationRule(
        rule_id="JWT-001",
        title="Insecure JWT algorithm configured",
        description=(
            "JWT handling permits the none algorithm, which can "
            "allow unsigned tokens to be accepted."
        ),
        category="authentication",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Reject unsigned JWTs and enforce an explicit allowlist "
            "of strong algorithms such as RS256 or ES256."
        ),
        cwe_id="CWE-347",
        owasp_reference="API2:2023",
    )

    JWT_VERIFY_DISABLED_RULE = PythonConfigurationRule(
        rule_id="JWT-002",
        title="JWT signature verification disabled",
        description=(
            "JWT decoding disables signature verification, allowing "
            "attackers to forge authentication tokens."
        ),
        category="authentication",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Enable JWT signature verification and validate issuer, "
            "audience, expiry, and the expected signing algorithm."
        ),
        cwe_id="CWE-347",
        owasp_reference="API2:2023",
    )

    CORS_WILDCARD_RULE = PythonConfigurationRule(
        rule_id="CORS-001",
        title="Overly permissive CORS configuration",
        description=(
            "The application allows requests from every origin. "
            "This may expose authenticated API responses to "
            "untrusted websites."
        ),
        category="security-misconfiguration",
        severity=SourceIssueSeverity.HIGH,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Replace wildcard origins with an explicit allowlist of "
            "trusted application origins."
        ),
        cwe_id="CWE-942",
        owasp_reference="API8:2023",
    )

    CORS_CREDENTIALS_RULE = PythonConfigurationRule(
        rule_id="CORS-002",
        title="Wildcard CORS with credentials enabled",
        description=(
            "CORS is configured with wildcard origins while "
            "credentials are enabled, creating an unsafe and "
            "potentially invalid cross-origin security policy."
        ),
        category="security-misconfiguration",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Use an explicit trusted-origin allowlist whenever "
            "cookies or authorization credentials are accepted."
        ),
        cwe_id="CWE-942",
        owasp_reference="API8:2023",
    )

    SENSITIVE_NAMES = {
        "api_key",
        "apikey",
        "api_secret",
        "access_token",
        "auth_token",
        "client_secret",
        "database_password",
        "db_password",
        "jwt_secret",
        "password",
        "private_key",
        "secret",
        "secret_key",
        "session_secret",
        "signing_key",
        "token",
    }

    PLACEHOLDER_VALUES = {
        "",
        "change-me",
        "changeme",
        "example",
        "placeholder",
        "replace-me",
        "replace_me",
        "secret",
        "test",
        "todo",
        "your-api-key",
        "your-secret",
    }

    HTTP_CLIENT_CALLS = {
        "httpx.delete",
        "httpx.get",
        "httpx.patch",
        "httpx.post",
        "httpx.put",
        "requests.delete",
        "requests.get",
        "requests.patch",
        "requests.post",
        "requests.put",
        "requests.request",
    }

    JWT_DECODE_CALLS = {
        "jose.jwt.decode",
        "jwt.decode",
        "pyjwt.decode",
    }

    SECRET_PATTERN = re.compile(
        r"(?i)"
        r"(?:sk|pk|api|key|token|secret|password|passwd|pwd)"
        r"[-_A-Za-z0-9]{8,}"
    )

    def analyze(
        self,
        *,
        files: list[SourceFile],
        context: SourceAnalysisContext,
    ) -> SourceAnalysisResult:
        issues: list[SourceIssue] = []
        errors: list[str] = []
        scanned = 0

        for source_file in files:
            if source_file.language != "python":
                continue

            scanned += 1

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

            visitor = _PythonConfigurationVisitor(
                source_file=source_file,
            )

            visitor.visit(
                tree,
            )

            issues.extend(
                visitor.issues,
            )

        result = SourceAnalysisResult(
            analyzer=self.name,
            files_scanned=scanned,
            issues=issues,
            errors=errors,
            metadata={
                "engine": "python-ast",
                "rule_ids": [
                    "SECRET-001",
                    "SECRET-002",
                    "CONFIG-001",
                    "TLS-001",
                    "JWT-001",
                    "JWT-002",
                    "CORS-001",
                    "CORS-002",
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
        line = error.lineno or 0
        message = error.msg or "invalid syntax"

        return (
            f"{source_file.relative_path}:{line}: "
            f"SyntaxError: {message}"
        )


class _PythonConfigurationVisitor(
    ast.NodeVisitor,
):
    def __init__(
        self,
        *,
        source_file: SourceFile,
    ) -> None:
        self.source_file = source_file
        self.issues: list[SourceIssue] = []
        self._scope_stack: list[
            tuple[str, str]
        ] = []

    def visit_ClassDef(
        self,
        node: ast.ClassDef,
    ) -> Any:
        self._scope_stack.append(
            (
                "class",
                node.name,
            ),
        )

        self.generic_visit(
            node,
        )

        self._scope_stack.pop()

        return node

    def visit_FunctionDef(
        self,
        node: ast.FunctionDef,
    ) -> Any:
        self._scope_stack.append(
            (
                "function",
                node.name,
            ),
        )

        self.generic_visit(
            node,
        )

        self._scope_stack.pop()

        return node

    def visit_AsyncFunctionDef(
        self,
        node: ast.AsyncFunctionDef,
    ) -> Any:
        self._scope_stack.append(
            (
                "function",
                node.name,
            ),
        )

        self.generic_visit(
            node,
        )

        self._scope_stack.pop()

        return node

    def visit_Assign(
        self,
        node: ast.Assign,
    ) -> Any:
        value = self._constant_string(
            node.value,
        )

        if value is not None:
            for target in node.targets:
                for variable_name in self._target_names(
                    target,
                ):
                    self._inspect_secret_assignment(
                        variable_name=variable_name,
                        value=value,
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
        value = self._constant_string(
            node.value,
        )

        if value is not None:
            for variable_name in self._target_names(
                node.target,
            ):
                self._inspect_secret_assignment(
                    variable_name=variable_name,
                    value=value,
                    node=node,
                )

        self.generic_visit(
            node,
        )

        return node

    def visit_Call(
        self,
        node: ast.Call,
    ) -> Any:
        call_name = self._call_name(
            node.func,
        )

        self._inspect_debug_configuration(
            node=node,
            call_name=call_name,
        )

        self._inspect_tls_verification(
            node=node,
            call_name=call_name,
        )

        self._inspect_jwt_configuration(
            node=node,
            call_name=call_name,
        )

        self._inspect_cors_configuration(
            node=node,
            call_name=call_name,
        )

        self.generic_visit(
            node,
        )

        return node

    def _inspect_secret_assignment(
        self,
        *,
        variable_name: str,
        value: str,
        node: ast.AST,
    ) -> None:
        normalized_name = self._normalize_name(
            variable_name,
        )

        if not self._is_sensitive_name(
            normalized_name,
        ):
            return

        normalized_value = value.strip()

        if normalized_value.lower() in (
            PythonConfigurationSecurityAnalyzer
            .PLACEHOLDER_VALUES
        ):
            self._add_issue(
                rule=(
                    PythonConfigurationSecurityAnalyzer
                    .WEAK_SECRET_RULE
                ),
                node=node,
                metadata={
                    "variable_name": variable_name,
                    "reason": "placeholder-value",
                },
                redact_evidence=True,
            )
            return

        if self._is_probable_hardcoded_secret(
            normalized_value,
        ):
            self._add_issue(
                rule=(
                    PythonConfigurationSecurityAnalyzer
                    .HARDCODED_SECRET_RULE
                ),
                node=node,
                metadata={
                    "variable_name": variable_name,
                    "secret_length": len(
                        normalized_value,
                    ),
                },
                redact_evidence=True,
            )

            if self._is_weak_secret(
                normalized_value,
            ):
                self._add_issue(
                    rule=(
                        PythonConfigurationSecurityAnalyzer
                        .WEAK_SECRET_RULE
                    ),
                    node=node,
                    metadata={
                        "variable_name": variable_name,
                        "reason": "low-entropy",
                    },
                    redact_evidence=True,
                )

    def _inspect_debug_configuration(
        self,
        *,
        node: ast.Call,
        call_name: str,
    ) -> None:
        debug_keyword = self._keyword(
            node,
            "debug",
        )

        if debug_keyword is None:
            return

        if not self._is_true(
            debug_keyword.value,
        ):
            return

        if (
            call_name.endswith(
                ".run",
            )
            or call_name in {
                "FastAPI",
                "Flask",
                "uvicorn.run",
            }
        ):
            self._add_issue(
                rule=(
                    PythonConfigurationSecurityAnalyzer
                    .DEBUG_RULE
                ),
                node=node,
                metadata={
                    "call": call_name,
                },
            )

    def _inspect_tls_verification(
        self,
        *,
        node: ast.Call,
        call_name: str,
    ) -> None:
        if not (
            call_name
            in PythonConfigurationSecurityAnalyzer
            .HTTP_CLIENT_CALLS
            or call_name.endswith(
                ".request",
            )
            or call_name.endswith(
                ".get",
            )
            or call_name.endswith(
                ".post",
            )
            or call_name.endswith(
                ".put",
            )
            or call_name.endswith(
                ".patch",
            )
            or call_name.endswith(
                ".delete",
            )
        ):
            return

        verify_keyword = self._keyword(
            node,
            "verify",
        )

        if verify_keyword is None:
            return

        if self._is_false(
            verify_keyword.value,
        ):
            self._add_issue(
                rule=(
                    PythonConfigurationSecurityAnalyzer
                    .VERIFY_DISABLED_RULE
                ),
                node=node,
                metadata={
                    "call": call_name,
                },
            )

    def _inspect_jwt_configuration(
        self,
        *,
        node: ast.Call,
        call_name: str,
    ) -> None:
        if not (
            call_name
            in PythonConfigurationSecurityAnalyzer
            .JWT_DECODE_CALLS
            or call_name.endswith(
                "jwt.decode",
            )
        ):
            return

        algorithms_keyword = self._keyword(
            node,
            "algorithms",
        )

        if algorithms_keyword is not None:
            algorithms = {
                value.lower()
                for value in self._string_values(
                    algorithms_keyword.value,
                )
            }

            if "none" in algorithms:
                self._add_issue(
                    rule=(
                        PythonConfigurationSecurityAnalyzer
                        .JWT_NONE_RULE
                    ),
                    node=node,
                    metadata={
                        "algorithms": sorted(
                            algorithms,
                        ),
                    },
                )

        options_keyword = self._keyword(
            node,
            "options",
        )

        if options_keyword is not None:
            options = self._literal_dict(
                options_keyword.value,
            )

            if (
                options.get(
                    "verify_signature",
                )
                is False
            ):
                self._add_issue(
                    rule=(
                        PythonConfigurationSecurityAnalyzer
                        .JWT_VERIFY_DISABLED_RULE
                    ),
                    node=node,
                    metadata={
                        "option": "verify_signature",
                    },
                )

        verify_keyword = self._keyword(
            node,
            "verify",
        )

        if (
            verify_keyword is not None
            and self._is_false(
                verify_keyword.value,
            )
        ):
            self._add_issue(
                rule=(
                    PythonConfigurationSecurityAnalyzer
                    .JWT_VERIFY_DISABLED_RULE
                ),
                node=node,
                metadata={
                    "option": "verify",
                },
            )

    def _inspect_cors_configuration(
        self,
        *,
        node: ast.Call,
        call_name: str,
    ) -> None:
        middleware_keyword = self._keyword(
            node,
            "middleware_class",
        )

        is_cors_call = (
            call_name.endswith(
                "CORSMiddleware",
            )
            or (
                call_name.endswith(
                    ".add_middleware",
                )
                and node.args
                and self._call_name(
                    node.args[0],
                ).endswith(
                    "CORSMiddleware",
                )
            )
            or (
                middleware_keyword is not None
                and self._call_name(
                    middleware_keyword.value,
                ).endswith(
                    "CORSMiddleware",
                )
            )
        )

        if not is_cors_call:
            return

        origins_keyword = self._keyword(
            node,
            "allow_origins",
        )

        if origins_keyword is None:
            return

        origins = self._string_values(
            origins_keyword.value,
        )

        if "*" not in origins:
            return

        credentials_keyword = self._keyword(
            node,
            "allow_credentials",
        )

        if (
            credentials_keyword is not None
            and self._is_true(
                credentials_keyword.value,
            )
        ):
            self._add_issue(
                rule=(
                    PythonConfigurationSecurityAnalyzer
                    .CORS_CREDENTIALS_RULE
                ),
                node=node,
                metadata={
                    "allow_origins": [
                        "*",
                    ],
                    "allow_credentials": True,
                },
            )
            return

        self._add_issue(
            rule=(
                PythonConfigurationSecurityAnalyzer
                .CORS_WILDCARD_RULE
            ),
            node=node,
            metadata={
                "allow_origins": [
                    "*",
                ],
            },
        )

    def _add_issue(
        self,
        *,
        rule: PythonConfigurationRule,
        node: ast.AST,
        metadata: dict[str, Any] | None = None,
        redact_evidence: bool = False,
    ) -> None:
        function_name = self._current_scope(
            "function",
        )

        class_name = self._current_scope(
            "class",
        )

        evidence = self._source_segment(
            node,
        )

        if redact_evidence:
            evidence = self._redacted_evidence(
                evidence,
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
                    column_start=self._column_number(
                        node,
                        "col_offset",
                    ),
                    column_end=self._column_number(
                        node,
                        "end_col_offset",
                    ),
                    function_name=function_name,
                    class_name=class_name,
                ),
                evidence=evidence,
                cwe_id=rule.cwe_id,
                owasp_reference=rule.owasp_reference,
                metadata={
                    "analyzer": (
                        PythonConfigurationSecurityAnalyzer
                        .name
                    ),
                    "language": "python",
                    **rule.metadata,
                    **(
                        metadata
                        or {}
                    ),
                },
            ),
        )

    @staticmethod
    def _normalize_name(
        value: str,
    ) -> str:
        normalized = value.strip()

        # Convert acronym boundaries:
        # APIKey -> API_Key
        # JWTSecret -> JWT_Secret
        normalized = re.sub(
            r"([A-Z]+)([A-Z][a-z])",
            lambda match: (
                f"{match.group(1)}_"
                f"{match.group(2)}"
            ),
            normalized,
        )

        # Convert camelCase boundaries:
        # clientSecret -> client_Secret
        normalized = re.sub(
            r"([a-z0-9])([A-Z])",
            lambda match: (
                f"{match.group(1)}_"
                f"{match.group(2)}"
            ),
            normalized,
        )

        normalized = re.sub(
            r"[^A-Za-z0-9]+",
            "_",
            normalized,
        )

        normalized = re.sub(
            r"_+",
            "_",
            normalized,
        )

        return normalized.strip(
            "_",
        ).lower()

    @staticmethod
    def _is_sensitive_name(
        normalized_name: str,
    ) -> bool:
        normalized = normalized_name.lower()

        keywords = (
            "secret",
            "secret_key",
            "jwt_secret",
            "session_secret",
            "client_secret",
            "private_key",
            "signing_key",
            "password",
            "passwd",
            "pwd",
            "db_password",
            "database_password",
            "token",
            "access_token",
            "refresh_token",
            "auth_token",
            "api_key",
            "apikey",
        )

        return any(
            keyword in normalized
            for keyword in keywords
        )


    @classmethod
    def _is_probable_hardcoded_secret(
        cls,
        value: str,
    ) -> bool:
        if len(
            value,
        ) < 8:
            return False

        if value.startswith(
            (
                "${",
                "{{",
                "env:",
                "os.getenv",
            ),
        ):
            return False

        if cls._looks_like_url(
            value,
        ):
            return False

        return (
            bool(
                PythonConfigurationSecurityAnalyzer
                .SECRET_PATTERN.search(
                    value,
                )
            )
            or (
                len(value) >= 16
                and not value.lower().startswith(
                    (
                        "http://",
                        "https://",
                        "postgres://",
                        "postgresql://",
                        "mysql://",
                        "sqlite://",
                    )
                )
            )
        )

    @classmethod
    def _is_weak_secret(
        cls,
        value: str,
    ) -> bool:
        if len(
            value,
        ) < 16:
            return True

        entropy = cls._shannon_entropy(
            value,
        )

        return entropy < 3.0

    @staticmethod
    def _shannon_entropy(
        value: str,
    ) -> float:
        if not value:
            return 0.0

        frequencies: dict[
            str,
            int,
        ] = {}

        for character in value:
            frequencies[
                character
            ] = frequencies.get(
                character,
                0,
            ) + 1

        length = len(
            value,
        )

        return -sum(
            (
                count
                / length
            )
            * math.log2(
                count
                / length,
            )
            for count in frequencies.values()
        )

    @staticmethod
    def _looks_like_url(
        value: str,
    ) -> bool:
        lowered = value.lower()

        return lowered.startswith(
            (
                "http://",
                "https://",
                "postgresql://",
                "mysql://",
                "sqlite://",
            ),
        )

    @staticmethod
    def _constant_string(
        node: ast.AST | None,
    ) -> str | None:
        if isinstance(
            node,
            ast.Constant,
        ) and isinstance(
            node.value,
            str,
        ):
            return node.value

        return None

    @classmethod
    def _target_names(
        cls,
        node: ast.AST,
    ) -> list[str]:
        if isinstance(
            node,
            ast.Name,
        ):
            return [
                node.id,
            ]

        if isinstance(
            node,
            ast.Attribute,
        ):
            return [
                node.attr,
            ]

        if isinstance(
            node,
            (
                ast.Tuple,
                ast.List,
            ),
        ):
            names: list[str] = []

            for element in node.elts:
                names.extend(
                    cls._target_names(
                        element,
                    ),
                )

            return names

        return []

    @staticmethod
    def _keyword(
        node: ast.Call,
        name: str,
    ) -> ast.keyword | None:
        for keyword in node.keywords:
            if keyword.arg == name:
                return keyword

        return None

    @staticmethod
    def _is_true(
        node: ast.AST,
    ) -> bool:
        return (
            isinstance(
                node,
                ast.Constant,
            )
            and node.value is True
        )

    @staticmethod
    def _is_false(
        node: ast.AST,
    ) -> bool:
        return (
            isinstance(
                node,
                ast.Constant,
            )
            and node.value is False
        )

    @classmethod
    def _string_values(
        cls,
        node: ast.AST,
    ) -> list[str]:
        if isinstance(
            node,
            ast.Constant,
        ) and isinstance(
            node.value,
            str,
        ):
            return [
                node.value,
            ]

        if isinstance(
            node,
            (
                ast.List,
                ast.Tuple,
                ast.Set,
            ),
        ):
            values: list[str] = []

            for element in node.elts:
                values.extend(
                    cls._string_values(
                        element,
                    ),
                )

            return values

        return []

    @staticmethod
    def _literal_dict(
        node: ast.AST,
    ) -> dict[str, Any]:
        if not isinstance(
            node,
            ast.Dict,
        ):
            return {}

        result: dict[
            str,
            Any,
        ] = {}

        for key_node, value_node in zip(
            node.keys,
            node.values,
            strict=False,
        ):
            if not isinstance(
                key_node,
                ast.Constant,
            ):
                continue

            if not isinstance(
                key_node.value,
                str,
            ):
                continue

            if isinstance(
                value_node,
                ast.Constant,
            ):
                result[
                    key_node.value
                ] = value_node.value

        return result

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

    def _source_segment(
        self,
        node: ast.AST,
    ) -> str | None:
        segment = ast.get_source_segment(
            self.source_file.content,
            node,
        )

        if segment is None:
            return None

        normalized = " ".join(
            segment.strip().split(),
        )

        return normalized[:500]

    @staticmethod
    def _redacted_evidence(
        evidence: str | None,
    ) -> str | None:
        if not evidence:
            return evidence

        assignment_match = re.match(
            r"^(.*?=\s*)([rubfRUBF]*)(['\"]{1,3}).*$",
            evidence,
        )

        if assignment_match:
            prefix = assignment_match.group(
                1,
            )

            quote_prefix = assignment_match.group(
                2,
            )

            quote = assignment_match.group(
                3,
            )

            return (
                f"{prefix}{quote_prefix}{quote}"
                f"[REDACTED]{quote}"
            )

        return "[REDACTED]"

    def _current_scope(
        self,
        scope_type: str,
    ) -> str | None:
        for current_type, name in reversed(
            self._scope_stack,
        ):
            if current_type == scope_type:
                return name

        return None

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
