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
class PythonSecurityRule:
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


class PythonASTSecurityAnalyzer(
    SourceAnalyzer,
):
    name = "python-ast-security"

    languages = (
        "python",
    )

    priority = 100

    EVAL_RULE = PythonSecurityRule(
        rule_id="CODE-001",
        title="Unsafe eval usage",
        description=(
            "The eval function dynamically executes a Python "
            "expression and may allow arbitrary code execution "
            "when influenced by untrusted input."
        ),
        category="code-injection",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Remove eval and use an explicit parser, allowlist, "
            "or ast.literal_eval for trusted literal structures."
        ),
        cwe_id="CWE-95",
        owasp_reference="API8:2023",
    )

    EXEC_RULE = PythonSecurityRule(
        rule_id="CODE-002",
        title="Unsafe exec usage",
        description=(
            "The exec function dynamically executes Python code "
            "and can permit arbitrary code execution."
        ),
        category="code-injection",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Remove exec and replace dynamic execution with "
            "explicitly implemented application logic."
        ),
        cwe_id="CWE-95",
        owasp_reference="API8:2023",
    )

    SHELL_RULE = PythonSecurityRule(
        rule_id="CMD-001",
        title="Subprocess shell execution enabled",
        description=(
            "A subprocess call enables shell execution. Untrusted "
            "command content may result in operating-system command "
            "injection."
        ),
        category="command-injection",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Set shell=False, pass the command as an argument list, "
            "and validate every externally controlled argument."
        ),
        cwe_id="CWE-78",
        owasp_reference="API8:2023",
    )

    OS_SYSTEM_RULE = PythonSecurityRule(
        rule_id="CMD-002",
        title="Unsafe os.system usage",
        description=(
            "os.system executes a command through the operating "
            "system shell and may enable command injection."
        ),
        category="command-injection",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Replace os.system with subprocess.run using an argument "
            "list, shell=False, strict validation, and a timeout."
        ),
        cwe_id="CWE-78",
        owasp_reference="API8:2023",
    )

    PICKLE_RULE = PythonSecurityRule(
        rule_id="DESER-001",
        title="Unsafe pickle deserialization",
        description=(
            "Python pickle deserialization may execute attacker-"
            "controlled code when the serialized data is untrusted."
        ),
        category="unsafe-deserialization",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Do not deserialize untrusted pickle data. Use a safe "
            "format such as JSON with strict schema validation."
        ),
        cwe_id="CWE-502",
        owasp_reference="API8:2023",
    )

    YAML_RULE = PythonSecurityRule(
        rule_id="DESER-002",
        title="Unsafe YAML loading",
        description=(
            "yaml.load may construct arbitrary Python objects when "
            "used without a safe loader."
        ),
        category="unsafe-deserialization",
        severity=SourceIssueSeverity.HIGH,
        confidence=SourceIssueConfidence.HIGH,
        remediation=(
            "Use yaml.safe_load or explicitly configure SafeLoader."
        ),
        cwe_id="CWE-502",
        owasp_reference="API8:2023",
    )

    SQL_RULE = PythonSecurityRule(
        rule_id="SQL-001",
        title="Potential SQL injection",
        description=(
            "A dynamically constructed SQL statement is passed to "
            "a database execution method."
        ),
        category="sql-injection",
        severity=SourceIssueSeverity.CRITICAL,
        confidence=SourceIssueConfidence.MEDIUM,
        remediation=(
            "Use parameterized queries or ORM query builders. Never "
            "concatenate, format, or interpolate untrusted values "
            "into SQL statements."
        ),
        cwe_id="CWE-89",
        owasp_reference="API8:2023",
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

            visitor = _PythonSecurityVisitor(
                source_file=source_file,
            )

            visitor.visit(
                tree,
            )

            issues.extend(
                visitor.issues,
            )

        return SourceAnalysisResult(
            analyzer=self.name,
            files_scanned=scanned,
            issues=issues,
            errors=errors,
            metadata={
                "engine": "python-ast",
                "rule_ids": [
                    "CODE-001",
                    "CODE-002",
                    "CMD-001",
                    "CMD-002",
                    "DESER-001",
                    "DESER-002",
                    "SQL-001",
                ],
            },
        ).deduplicate()

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


class _PythonSecurityVisitor(
    ast.NodeVisitor,
):
    SQL_EXECUTION_METHODS = {
        "execute",
        "executemany",
        "exec_driver_sql",
    }

    SUBPROCESS_FUNCTIONS = {
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.run",
    }

    PICKLE_FUNCTIONS = {
        "pickle.load",
        "pickle.loads",
        "cPickle.load",
        "cPickle.loads",
    }

    YAML_LOAD_FUNCTIONS = {
        "yaml.load",
    }

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

    def visit_Call(
        self,
        node: ast.Call,
    ) -> Any:
        call_name = self._call_name(
            node.func,
        )

        if call_name == "eval":
            self._add_issue(
                rule=PythonASTSecurityAnalyzer.EVAL_RULE,
                node=node,
            )

        elif call_name == "exec":
            self._add_issue(
                rule=PythonASTSecurityAnalyzer.EXEC_RULE,
                node=node,
            )

        elif call_name == "os.system":
            self._add_issue(
                rule=PythonASTSecurityAnalyzer.OS_SYSTEM_RULE,
                node=node,
            )

        elif call_name in self.SUBPROCESS_FUNCTIONS:
            if self._has_truthy_keyword(
                node=node,
                keyword_name="shell",
            ):
                self._add_issue(
                    rule=PythonASTSecurityAnalyzer.SHELL_RULE,
                    node=node,
                )

        elif call_name in self.PICKLE_FUNCTIONS:
            self._add_issue(
                rule=PythonASTSecurityAnalyzer.PICKLE_RULE,
                node=node,
            )

        elif call_name in self.YAML_LOAD_FUNCTIONS:
            if not self._uses_safe_yaml_loader(
                node,
            ):
                self._add_issue(
                    rule=PythonASTSecurityAnalyzer.YAML_RULE,
                    node=node,
                )

        if self._is_sql_execution_call(
            call_name,
        ):
            if (
                node.args
                and self._is_dynamic_expression(
                    node.args[0],
                )
            ):
                self._add_issue(
                    rule=PythonASTSecurityAnalyzer.SQL_RULE,
                    node=node,
                )

        self.generic_visit(
            node,
        )

        return node

    def _add_issue(
        self,
        *,
        rule: PythonSecurityRule,
        node: ast.AST,
    ) -> None:
        function_name = self._current_scope(
            "function",
        )

        class_name = self._current_scope(
            "class",
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
                evidence=self._source_segment(
                    node,
                ),
                cwe_id=rule.cwe_id,
                owasp_reference=rule.owasp_reference,
                metadata={
                    "analyzer": (
                        PythonASTSecurityAnalyzer.name
                    ),
                    "language": "python",
                    **rule.metadata,
                },
            ),
        )

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

    @staticmethod
    def _has_truthy_keyword(
        *,
        node: ast.Call,
        keyword_name: str,
    ) -> bool:
        for keyword in node.keywords:
            if keyword.arg != keyword_name:
                continue

            value = keyword.value

            if isinstance(
                value,
                ast.Constant,
            ):
                return value.value is True

            if isinstance(
                value,
                ast.Name,
            ):
                return value.id.lower() == "true"

            return True

        return False

    @classmethod
    def _uses_safe_yaml_loader(
        cls,
        node: ast.Call,
    ) -> bool:
        for keyword in node.keywords:
            if keyword.arg != "Loader":
                continue

            loader_name = cls._call_name(
                keyword.value,
            )

            return loader_name.endswith(
                "SafeLoader",
            )

        return False

    @classmethod
    def _is_sql_execution_call(
        cls,
        call_name: str,
    ) -> bool:
        method_name = call_name.rsplit(
            ".",
            1,
        )[-1]

        return (
            method_name
            in cls.SQL_EXECUTION_METHODS
        )

    @staticmethod
    def _is_dynamic_expression(
        node: ast.AST,
    ) -> bool:
        if isinstance(
            node,
            ast.JoinedStr,
        ):
            return True

        if isinstance(
            node,
            ast.BinOp,
        ):
            return isinstance(
                node.op,
                (
                    ast.Add,
                    ast.Mod,
                ),
            )

        if isinstance(
            node,
            ast.Call,
        ):
            call_name = (
                _PythonSecurityVisitor
                ._call_name(
                    node.func,
                )
            )

            return (
                call_name == "format"
                or call_name.endswith(
                    ".format",
                )
            )

        return False
