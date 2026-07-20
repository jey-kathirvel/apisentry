"""
API Sentry
FastAPI Response Parser

Static AST parser for response metadata.

This module never imports or executes the analyzed project.
"""

from __future__ import annotations

import ast

from dataclasses import dataclass
from dataclasses import field
from typing import Iterable
from app.services.discovery.status_code_resolver import StatusCodeResolverMixin


@dataclass(slots=True)
class ResponseDiscovery:
    """
    Represents one possible HTTP response.
    """

    status_code: int
    model: str | None = None
    description: str | None = None


@dataclass(slots=True)
class ResponseSummary:
    """
    Aggregated response metadata.
    """

    default_status_code: int | None = None

    response_model: str | None = None

    responses: list[ResponseDiscovery] = field(
        default_factory=list,
    )


class FastAPIResponseParserMixin(
    StatusCodeResolverMixin,
):
    """
    Response parser.
    """

    def _discover_route_responses(
        self,
        decorator: ast.Call,
    ) -> ResponseSummary:

        summary = ResponseSummary()

        summary.default_status_code = (
            self._extract_status_code(
                decorator,
            )
        )

        summary.response_model = (
            self._extract_response_model(
                decorator,
            )
        )

        summary.responses.extend(
            self._extract_declared_responses(
                decorator,
            )
        )

        return summary

    def _discover_function_body_responses(
        self,
        function_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> ResponseSummary:
        """
        Infer responses from the endpoint implementation.
        """

        summary = ResponseSummary()

        responses: list[ResponseDiscovery] = []

        for node in ast.walk(function_node):

            if isinstance(node, ast.Return):

                responses.extend(
                    self._discover_return_response(
                        node.value,
                    )
                )

            elif isinstance(node, ast.Raise):

                responses.extend(
                    self._discover_exception_response(
                        node.exc,
                    )
                )

        summary.responses = self._deduplicate_responses(
            responses,
        )

        return summary


    def _discover_return_response(
        self,
        node: ast.AST | None,
    ) -> list[ResponseDiscovery]:

        if node is None:
            return []

        if not isinstance(node, ast.Call):
            return []

        callable_name = self._callable_name(node)

        if callable_name.endswith("JSONResponse"):

            status = self._keyword_int(
                node,
                "status_code",
            )

            if status is None:
                status = 200

            return [
                ResponseDiscovery(
                    status_code=status,
                    model="JSONResponse",
                )
            ]

        if callable_name.endswith("Response"):

            status = self._keyword_int(
                node,
                "status_code",
            )

            if status is None:
                status = 200

            return [
                ResponseDiscovery(
                    status_code=status,
                    model="Response",
                )
            ]

        return []


    def _discover_exception_response(
        self,
        node: ast.AST | None,
    ) -> list[ResponseDiscovery]:

        if not isinstance(node, ast.Call):
            return []

        callable_name = self._callable_name(node)

        if not callable_name.endswith("HTTPException"):
            return []

        status = self._keyword_int(
            node,
            "status_code",
        )

        if status is None:
            return []

        description = self._keyword_string(
            node,
            "detail",
        )

        return [
            ResponseDiscovery(
                status_code=status,
                description=description,
            )
        ]


    def _merge_response_summaries(
        self,
        *summaries: ResponseSummary,
    ) -> ResponseSummary:

        merged = ResponseSummary()

        responses: list[
            ResponseDiscovery
        ] = []

        for summary in summaries:

            if (
                merged.default_status_code
                is None
                and summary.default_status_code
                is not None
            ):
                merged.default_status_code = (
                    summary.default_status_code
                )

            if (
                merged.response_model
                is None
                and summary.response_model
            ):
                merged.response_model = (
                    summary.response_model
                )

            responses.extend(
                summary.responses,
            )

        merged.responses = (
            self._deduplicate_responses(
                responses,
            )
        )

        return merged


    @staticmethod
    def _callable_name(
        call: ast.Call,
    ) -> str:

        node = call.func

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):

            names = []

            while isinstance(
                node,
                ast.Attribute,
            ):
                names.append(
                    node.attr,
                )
                node = node.value

            if isinstance(node, ast.Name):
                names.append(
                    node.id,
                )

            return ".".join(
                reversed(names),
            )

        return ""


    def _keyword_int(
        self,
        call: ast.Call,
        keyword_name: str,
    ) -> int | None:

        node = self._keyword_value(
            call,
            keyword_name,
        )

        return self.resolve_status_code(
            node,
        )


    def _keyword_string(
        self,
        call: ast.Call,
        keyword_name: str,
    ) -> str | None:

        node = self._keyword_value(
            call,
            keyword_name,
        )

        return self._literal_string(
            node,
        )

    def _extract_status_code(
        self,
        decorator: ast.Call,
    ) -> int | None:

        value = self._keyword_value(
            decorator,
            "status_code",
        )

        if isinstance(
            value,
            ast.Constant,
        ):

            if isinstance(
                value.value,
                int,
            ):
                return value.value

        return None

    def _extract_response_model(
        self,
        decorator: ast.Call,
    ) -> str | None:

        value = self._keyword_value(
            decorator,
            "response_model",
        )

        if value is None:
            return None

        return self._expression(
            value,
        )

    def _extract_declared_responses(
        self,
        decorator: ast.Call,
    ) -> list[ResponseDiscovery]:

        keyword = self._keyword_value(
            decorator,
            "responses",
        )

        if not isinstance(
            keyword,
            ast.Dict,
        ):
            return []

        responses: list[
            ResponseDiscovery
        ] = []

        for key_node, value_node in zip(
            keyword.keys,
            keyword.values,
            strict=True,
        ):

            status = self._literal_int(
                key_node,
            )

            if status is None:
                continue

            model = None
            description = None

            if isinstance(
                value_node,
                ast.Dict,
            ):

                for k, v in zip(
                    value_node.keys,
                    value_node.values,
                    strict=True,
                ):

                    key = self._literal_string(
                        k,
                    )

                    if key == "model":
                        model = self._expression(
                            v,
                        )

                    elif key == "description":
                        description = (
                            self._literal_string(
                                v,
                            )
                        )

            responses.append(
                ResponseDiscovery(
                    status_code=status,
                    model=model,
                    description=description,
                )
            )

        return responses

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
    def _literal_int(
        node: ast.AST | None,
    ) -> int | None:

        if isinstance(
            node,
            ast.Constant,
        ):

            if isinstance(
                node.value,
                int,
            ):
                return node.value

        return None

    @staticmethod
    def _literal_string(
        node: ast.AST | None,
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

        return None

    @staticmethod
    def _expression(
        node: ast.AST,
    ) -> str:

        try:
            return ast.unparse(
                node,
            )

        except Exception:
            return ""

    @staticmethod
    def _deduplicate_responses(
        responses: Iterable[
            ResponseDiscovery
        ],
    ) -> list[
        ResponseDiscovery
    ]:

        result = []

        seen = set()

        for response in responses:

            key = (
                response.status_code,
                response.model,
                response.description,
            )

            if key in seen:
                continue

            seen.add(
                key,
            )

            result.append(
                response,
            )

        return result
    def _enrich_discovered_endpoint_responses(
        self,
        tree: ast.Module,
    ) -> None:
        """
        Add decorator and function-body response metadata to
        discovered endpoints.
        """

        endpoints = list(
            getattr(
                self,
                "endpoints",
                [],
            )
            or []
        )

        if not endpoints:
            return

        router_definitions = getattr(
            self,
            "router_definitions",
            {},
        )

        for function_node in ast.walk(
            tree,
        ):
            if not isinstance(
                function_node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                ),
            ):
                continue

            function_summary = (
                self._discover_function_body_responses(
                    function_node,
                )
            )

            for decorator_node in function_node.decorator_list:
                if not isinstance(
                    decorator_node,
                    ast.Call,
                ):
                    continue

                parsed_route = (
                    self._response_route_identity(
                        decorator_node,
                    )
                )

                if parsed_route is None:
                    continue

                (
                    router_variable,
                    method,
                    route_path,
                ) = parsed_route

                router_prefix = ""

                router_definition = (
                    router_definitions.get(
                        router_variable,
                    )
                )

                if router_definition is not None:
                    router_prefix = str(
                        getattr(
                            router_definition,
                            "prefix",
                            "",
                        )
                        or ""
                    )

                full_path = self.join_paths(
                    router_prefix,
                    route_path,
                )

                endpoint = (
                    self._find_response_endpoint(
                        endpoints=endpoints,
                        method=method,
                        full_path=full_path,
                        function_name=function_node.name,
                    )
                )

                if endpoint is None:
                    continue

                decorator_summary = (
                    self._discover_route_responses(
                        decorator_node,
                    )
                )

                merged_summary = (
                    self._merge_response_summaries(
                        decorator_summary,
                        function_summary,
                    )
                )

                endpoint.default_status_code = (
                    merged_summary.default_status_code
                )

                endpoint.response_model = (
                    merged_summary.response_model
                )

                endpoint.responses = list(
                    merged_summary.responses
                )

    @staticmethod
    def _response_route_identity(
        decorator: ast.Call,
    ) -> tuple[str, str, str] | None:
        """
        Extract router variable, HTTP method and route path from a
        FastAPI route decorator.
        """

        if not isinstance(
            decorator.func,
            ast.Attribute,
        ):
            return None

        method = decorator.func.attr.upper()

        supported_methods = {
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
            "HEAD",
            "TRACE",
        }

        if method not in supported_methods:
            return None

        router_node = decorator.func.value

        if isinstance(
            router_node,
            ast.Name,
        ):
            router_variable = router_node.id
        else:
            try:
                router_variable = ast.unparse(
                    router_node,
                )
            except Exception:
                return None

        route_path = ""

        if decorator.args:
            path_node = decorator.args[0]

            if (
                isinstance(
                    path_node,
                    ast.Constant,
                )
                and isinstance(
                    path_node.value,
                    str,
                )
            ):
                route_path = path_node.value

        if not route_path:
            for keyword in decorator.keywords:
                if keyword.arg not in {
                    "path",
                    "route",
                }:
                    continue

                if (
                    isinstance(
                        keyword.value,
                        ast.Constant,
                    )
                    and isinstance(
                        keyword.value.value,
                        str,
                    )
                ):
                    route_path = (
                        keyword.value.value
                    )

                    break

        return (
            router_variable,
            method,
            route_path,
        )

    @staticmethod
    def _find_response_endpoint(
        endpoints: Iterable[object],
        method: str,
        full_path: str,
        function_name: str,
    ) -> object | None:
        """
        Locate the endpoint created by the main discovery pipeline.
        """

        normalized_method = method.upper()

        matches: list[object] = []

        for endpoint in endpoints:
            endpoint_method = str(
                getattr(
                    endpoint,
                    "method",
                    "",
                )
            ).upper()

            endpoint_path = str(
                getattr(
                    endpoint,
                    "full_path",
                    "",
                )
            )

            if (
                endpoint_method == normalized_method
                and endpoint_path == full_path
            ):
                matches.append(
                    endpoint,
                )

        if len(matches) == 1:
            return matches[0]

        for endpoint in matches:
            for attribute_name in (
                "function_name",
                "handler_name",
                "endpoint_name",
                "name",
            ):
                if (
                    getattr(
                        endpoint,
                        attribute_name,
                        None,
                    )
                    == function_name
                ):
                    return endpoint

        return (
            matches[0]
            if matches
            else None
        )

    def _resolve_declared_response_status(
        self,
        node: ast.AST | None,
    ) -> int | None:
        """
        Resolve integer and symbolic keys used in responses={...}.
        """

        return self.resolve_status_code(
            node,
        )
