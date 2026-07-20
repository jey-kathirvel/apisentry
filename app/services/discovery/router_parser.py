"""
API Sentry
FastAPI Router Parser

Static AST-based extraction of APIRouter definitions
and FastAPI route decorators.

Analyzed source code is never imported or executed.
"""

from __future__ import annotations

import ast

from app.services.discovery.models import RouteDecorator
from app.services.discovery.models import RouterDefinition


HTTP_METHODS: frozenset[str] = frozenset(
    {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "trace",
    }
)


class FastAPIRouterParserMixin:
    """
    Router and route-decorator parsing capabilities.
    """

    router_definitions: dict[
        str,
        RouterDefinition,
    ]

    def _scan_router_definitions(
        self,
        tree: ast.Module,
    ) -> None:
        for node in ast.walk(
            tree,
        ):
            if not isinstance(
                node,
                (
                    ast.Assign,
                    ast.AnnAssign,
                ),
            ):
                continue

            variable_name = self._assignment_name(
                node,
            )

            if not variable_name:
                continue

            value = self._assignment_value(
                node,
            )

            if not isinstance(
                value,
                ast.Call,
            ):
                continue

            constructor_name = self._qualified_name(
                value.func,
            )

            if not constructor_name:
                continue

            if (
                constructor_name != "APIRouter"
                and not constructor_name.endswith(
                    ".APIRouter"
                )
            ):
                continue

            router = RouterDefinition(
                variable_name=variable_name,
                prefix=(
                    self._call_string_keyword(
                        value,
                        "prefix",
                    )
                    or ""
                ),
                tags=self._call_string_list_keyword(
                    value,
                    "tags",
                ),
                dependencies=(
                    self._call_expression_list_keyword(
                        value,
                        "dependencies",
                    )
                ),
            )

            self.router_definitions[
                variable_name
            ] = router

    def _parse_route_decorator(
        self,
        decorator: ast.AST,
    ) -> RouteDecorator | None:
        if not isinstance(
            decorator,
            ast.Call,
        ):
            return None

        if not isinstance(
            decorator.func,
            ast.Attribute,
        ):
            return None

        method = decorator.func.attr.lower()

        if method not in HTTP_METHODS:
            return None

        router_variable = (
            self._qualified_name(
                decorator.func.value,
            )
            or ""
        )

        path = "/"

        if decorator.args:
            path_value = self._string(
                decorator.args[0],
            )

            if path_value is not None:
                path = path_value

        else:
            keyword_path = (
                self._call_string_keyword(
                    decorator,
                    "path",
                )
            )

            if keyword_path is not None:
                path = keyword_path

        return RouteDecorator(
            method=method.upper(),
            path=path,
            router_variable=router_variable,
            raw_node=decorator,
        )

    @staticmethod
    def _assignment_name(
        node: ast.Assign | ast.AnnAssign,
    ) -> str | None:
        if isinstance(
            node,
            ast.Assign,
        ):
            if len(node.targets) != 1:
                return None

            target = node.targets[0]

        else:
            target = node.target

        if isinstance(
            target,
            ast.Name,
        ):
            return target.id

        return None

    @staticmethod
    def _assignment_value(
        node: ast.Assign | ast.AnnAssign,
    ) -> ast.AST | None:
        return node.value
