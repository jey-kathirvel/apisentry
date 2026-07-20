"""
API Sentry
FastAPI AST Discovery Engine

PATCH-004
Part 3.1C

Static FastAPI endpoint discovery using Python AST.

The analyzer does not import or execute target application code.
"""

from __future__ import annotations

import ast


from pathlib import Path

from typing import Iterable

from app.services.discovery.models import EndpointDiscovery
from app.services.discovery.models import ParameterDiscovery
from app.services.discovery.models import RouteDecorator
from app.services.discovery.models import RouterDefinition
from app.services.discovery.parameter_parser import FastAPIParameterParserMixin
from app.services.discovery.ast_utils import FastAPIASTUtilsMixin
from app.services.discovery.dependency_parser import FastAPIDependencyParserMixin
from app.services.discovery.router_parser import FastAPIRouterParserMixin
from app.services.discovery.response_parser import FastAPIResponseParserMixin




class FastAPIASTDiscoveryError(RuntimeError):
    """Base FastAPI AST discovery exception."""


class FastAPIASTSyntaxError(
    FastAPIASTDiscoveryError,
):
    """Raised when a Python source file cannot be parsed."""


class FastAPIASTDiscovery(
    FastAPIRouterParserMixin,
    FastAPIASTUtilsMixin,
    FastAPIParameterParserMixin,
    FastAPIDependencyParserMixin,
    FastAPIResponseParserMixin,
):
    """
    Discover FastAPI endpoints without importing target code.
    """

    def __init__(self) -> None:
        self.router_definitions: dict[
            str,
            RouterDefinition,
        ] = {}

        self.endpoints: list[
            EndpointDiscovery
        ] = []

        self.errors: list[str] = []

        self.parameters: list[
            ParameterDiscovery
        ] = []

    def discover_file(
        self,
        python_file: str | Path,
    ) -> list[EndpointDiscovery]:
        path = Path(python_file)

        if not path.exists():
            raise FastAPIASTDiscoveryError(
                f"File does not exist: {path}"
            )

        if not path.is_file():
            raise FastAPIASTDiscoveryError(
                f"Path is not a file: {path}"
            )

        try:
            source = path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise FastAPIASTDiscoveryError(
                f"Unable to read file {path}: {exc}"
            ) from exc

        try:
            tree = ast.parse(
                source,
                filename=str(path),
            )
        except SyntaxError as exc:
            raise FastAPIASTSyntaxError(
                f"Unable to parse {path}: {exc}"
            ) from exc

        self.router_definitions = {}
        self.endpoints = []
        self.parameters = []

        self._scan_router_definitions(
            tree,
        )

        self._scan_route_functions(
            tree,
            path,
        )

        self._enrich_discovered_endpoint_security(
            tree,
        )

        self._enrich_discovered_endpoint_responses(
            tree,
        )

        return list(
            self.endpoints,
        )

    def get_parameters(
        self,
    ) -> list[ParameterDiscovery]:
        return list(
            self.parameters,
        )

    def discover_directory(
        self,
        files: Iterable[str | Path],
    ) -> list[EndpointDiscovery]:
        discovered_endpoints: list[
            EndpointDiscovery
        ] = []

        self.errors = []

        for file_path in files:
            try:
                discovered_endpoints.extend(
                    self.discover_file(
                        file_path,
                    )
                )
            except FastAPIASTDiscoveryError as exc:
                self.errors.append(
                    str(exc)
                )

        self.endpoints = discovered_endpoints

        return list(
            discovered_endpoints,
        )

    def get_endpoints(
        self,
    ) -> list[EndpointDiscovery]:
        return list(
            self.endpoints,
        )

    def get_errors(
        self,
    ) -> list[str]:
        return list(
            self.errors,
        )















    def _scan_route_functions(
        self,
        tree: ast.Module,
        file_path: Path,
    ) -> None:
        for node in ast.walk(tree):
            if not isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                ),
            ):
                continue

            for decorator in node.decorator_list:
                route = self._parse_route_decorator(
                    decorator,
                )

                if route is None:
                    continue

                router = self.router_definitions.get(
                    route.router_variable,
                )

                router_prefix = ""
                router_tags: list[str] = []
                router_dependencies: list[str] = []

                if router is not None:
                    router_prefix = router.prefix
                    router_tags = list(
                        router.tags,
                    )
                    router_dependencies = list(
                        router.dependencies,
                    )

                decorator_tags = (
                    self._call_string_list_keyword(
                        route.raw_node,
                        "tags",
                    )
                )

                dependencies = self._deduplicate(
                    router_dependencies
                    + self._call_expression_list_keyword(
                        route.raw_node,
                        "dependencies",
                    )
                )

                tags = self._deduplicate(
                    router_tags
                    + decorator_tags
                )

                parameters = self._discover_parameters(
                    node,
                    route.path,
                )

                endpoint = EndpointDiscovery(
                    method=route.method,
                    path=route.path,
                    router_prefix=router_prefix,
                    function_name=node.name,
                    file_path=str(file_path),
                    line_number=node.lineno,
                    router_variable=route.router_variable,
                    tags=tags,
                    summary=self._call_string_keyword(
                        route.raw_node,
                        "summary",
                    ),
                    description=(
                        self._call_string_keyword(
                            route.raw_node,
                            "description",
                        )
                        or ast.get_docstring(
                            node,
                            clean=True,
                        )
                    ),
                    deprecated=(
                        self._call_boolean_keyword(
                            route.raw_node,
                            "deprecated",
                        )
                        or False
                    ),
                    response_model=self._call_expression_keyword(
                        route.raw_node,
                        "response_model",
                    ),
                    status_code=self._call_integer_keyword(
                        route.raw_node,
                        "status_code",
                    ),
                    response_class=self._call_expression_keyword(
                        route.raw_node,
                        "response_class",
                    ),
                    operation_id=self._call_string_keyword(
                        route.raw_node,
                        "operation_id",
                    ),
                    dependencies=dependencies,
                    parameters=parameters,
                    authentication_required=(
                        self._dependencies_require_authentication(
                            dependencies
                        )
                    ),
                )

                self.endpoints.append(
                    endpoint,
                )

                self.parameters.extend(
                    parameters,
                )



















