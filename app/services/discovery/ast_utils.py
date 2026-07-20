"""
API Sentry
Python AST Utilities

Shared static AST helpers used by framework-specific
source-code discovery engines.

Analyzed source code is never imported or executed.
"""

from __future__ import annotations

import ast

from typing import Iterable


class FastAPIASTUtilsMixin:
    """
    Shared AST helper methods for FastAPI discovery.
    """

    @staticmethod
    def _qualified_name(
        node: ast.AST,
    ) -> str | None:
        if isinstance(
            node,
            ast.Name,
        ):
            return node.id

        if isinstance(
            node,
            ast.Attribute,
        ):
            parent = (
                FastAPIASTUtilsMixin._qualified_name(
                    node.value,
                )
            )

            if parent:
                return (
                    f"{parent}.{node.attr}"
                )

            return node.attr

        if isinstance(
            node,
            ast.Subscript,
        ):
            return (
                FastAPIASTUtilsMixin._qualified_name(
                    node.value,
                )
            )

        return None

    @staticmethod
    def _string(
        node: ast.AST,
    ) -> str | None:
        if isinstance(
            node,
            ast.Constant,
        ):
            if isinstance(
                node.value,
                str,
            ):
                return node.value

        if isinstance(
            node,
            ast.JoinedStr,
        ):
            values: list[str] = []

            for item in node.values:
                if (
                    isinstance(
                        item,
                        ast.Constant,
                    )
                    and isinstance(
                        item.value,
                        str,
                    )
                ):
                    values.append(
                        item.value,
                    )
                else:
                    return None

            return "".join(
                values,
            )

        return None

    @staticmethod
    def _boolean(
        node: ast.AST,
    ) -> bool | None:
        if (
            isinstance(
                node,
                ast.Constant,
            )
            and isinstance(
                node.value,
                bool,
            )
        ):
            return node.value

        return None

    @staticmethod
    def _integer(
        node: ast.AST,
    ) -> int | None:
        if isinstance(
            node,
            ast.Constant,
        ):
            if isinstance(
                node.value,
                bool,
            ):
                return None

            if isinstance(
                node.value,
                int,
            ):
                return node.value

        return None

    @staticmethod
    def _keyword_value(
        call: ast.Call,
        keyword_name: str,
    ) -> ast.AST | None:
        for keyword in call.keywords:
            if keyword.arg == keyword_name:
                return keyword.value

        return None

    @staticmethod
    def _call_string_keyword(
        call: ast.Call,
        keyword_name: str,
    ) -> str | None:
        value = (
            FastAPIASTUtilsMixin._keyword_value(
                call,
                keyword_name,
            )
        )

        if value is None:
            return None

        return FastAPIASTUtilsMixin._string(
            value,
        )

    @staticmethod
    def _call_boolean_keyword(
        call: ast.Call,
        keyword_name: str,
    ) -> bool | None:
        value = (
            FastAPIASTUtilsMixin._keyword_value(
                call,
                keyword_name,
            )
        )

        if value is None:
            return None

        return FastAPIASTUtilsMixin._boolean(
            value,
        )

    @staticmethod
    def _call_integer_keyword(
        call: ast.Call,
        keyword_name: str,
    ) -> int | None:
        value = (
            FastAPIASTUtilsMixin._keyword_value(
                call,
                keyword_name,
            )
        )

        if value is None:
            return None

        return FastAPIASTUtilsMixin._integer(
            value,
        )

    @staticmethod
    def _call_string_list_keyword(
        call: ast.Call,
        keyword_name: str,
    ) -> list[str]:
        value = (
            FastAPIASTUtilsMixin._keyword_value(
                call,
                keyword_name,
            )
        )

        if not isinstance(
            value,
            (
                ast.List,
                ast.Tuple,
                ast.Set,
            ),
        ):
            return []

        result: list[str] = []

        for item in value.elts:
            string_value = (
                FastAPIASTUtilsMixin._string(
                    item,
                )
            )

            if string_value is not None:
                result.append(
                    string_value,
                )

        return result

    @staticmethod
    def _call_expression_keyword(
        call: ast.Call,
        keyword_name: str,
    ) -> str | None:
        value = (
            FastAPIASTUtilsMixin._keyword_value(
                call,
                keyword_name,
            )
        )

        if value is None:
            return None

        return FastAPIASTUtilsMixin._expression_text(
            value,
        )

    @staticmethod
    def _call_expression_list_keyword(
        call: ast.Call,
        keyword_name: str,
    ) -> list[str]:
        value = (
            FastAPIASTUtilsMixin._keyword_value(
                call,
                keyword_name,
            )
        )

        if value is None:
            return []

        if isinstance(
            value,
            (
                ast.List,
                ast.Tuple,
                ast.Set,
            ),
        ):
            expressions = list(
                value.elts,
            )
        else:
            expressions = [
                value,
            ]

        result: list[str] = []

        for expression in expressions:
            expression_text = (
                FastAPIASTUtilsMixin._expression_text(
                    expression,
                )
            )

            if expression_text:
                result.append(
                    expression_text,
                )

        return result

    @staticmethod
    def _expression_text(
        node: ast.AST,
    ) -> str | None:
        try:
            return ast.unparse(
                node,
            )
        except Exception:
            return (
                FastAPIASTUtilsMixin._qualified_name(
                    node,
                )
            )

    @staticmethod
    def _dependencies_require_authentication(
        dependencies: Iterable[str],
    ) -> bool:
        authentication_markers = (
            "oauth",
            "auth",
            "token",
            "bearer",
            "apikey",
            "api_key",
            "current_user",
            "logged_in",
            "session_user",
            "permission",
            "security",
        )

        for dependency in dependencies:
            normalized = dependency.lower()

            if any(
                marker in normalized
                for marker in authentication_markers
            ):
                return True

        return False

    @staticmethod
    def _deduplicate(
        values: Iterable[str],
    ) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()

        for value in values:
            if value in seen:
                continue

            seen.add(
                value,
            )

            result.append(
                value,
            )

        return result

    @staticmethod
    def join_paths(
        prefix: str,
        path: str,
    ) -> str:
        clean_prefix = prefix.strip()
        clean_path = path.strip()

        if not clean_prefix:
            clean_prefix = ""

        elif not clean_prefix.startswith(
            "/"
        ):
            clean_prefix = (
                f"/{clean_prefix}"
            )

        clean_prefix = clean_prefix.rstrip(
            "/"
        )

        if not clean_path:
            clean_path = "/"

        elif not clean_path.startswith(
            "/"
        ):
            clean_path = (
                f"/{clean_path}"
            )

        full_path = (
            f"{clean_prefix}{clean_path}"
        )

        return full_path or "/"
