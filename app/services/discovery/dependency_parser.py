"""
API Sentry
FastAPI Dependency and Security Parser

Performs static AST analysis of FastAPI Depends(...)
and Security(...) declarations.

Analyzed project code is never imported or executed.
"""

from __future__ import annotations

import ast

from dataclasses import dataclass
from dataclasses import field
from typing import Iterable


DEPENDENCY_CALL_NAMES: frozenset[str] = frozenset(
    {
        "Depends",
        "Security",
    }
)


SECURITY_CONSTRUCTOR_NAMES: frozenset[str] = frozenset(
    {
        "APIKeyCookie",
        "APIKeyHeader",
        "APIKeyQuery",
        "HTTPBasic",
        "HTTPBearer",
        "HTTPDigest",
        "OAuth2",
        "OAuth2AuthorizationCodeBearer",
        "OAuth2PasswordBearer",
        "OpenIdConnect",
        "SecurityScopes",
    }
)


AUTHENTICATION_MARKERS: tuple[str, ...] = (
    "api_key",
    "apikey",
    "auth",
    "bearer",
    "credential",
    "current_account",
    "current_admin",
    "current_customer",
    "current_employee",
    "current_member",
    "current_user",
    "decode_token",
    "jwt",
    "logged_in",
    "login",
    "oauth",
    "permission",
    "require_user",
    "security",
    "session_user",
    "token",
)


PERMISSION_MARKERS: tuple[str, ...] = (
    "access",
    "admin",
    "authorize",
    "permission",
    "policy",
    "privilege",
    "require_role",
    "role",
    "scope",
)


@dataclass(slots=True)
class DependencyDiscovery:
    """
    Static representation of one FastAPI dependency declaration.
    """

    expression: str
    dependency_name: str | None = None
    declaration_type: str = "Depends"
    security_scheme: str | None = None
    scopes: list[str] = field(
        default_factory=list,
    )
    authentication_required: bool = False
    permission_required: bool = False
    use_cache: bool | None = None


@dataclass(slots=True)
class DependencySecuritySummary:
    """
    Aggregated dependency and security information.
    """

    dependencies: list[str] = field(
        default_factory=list,
    )
    security_schemes: list[str] = field(
        default_factory=list,
    )
    scopes: list[str] = field(
        default_factory=list,
    )
    authentication_required: bool = False
    permission_required: bool = False
    discoveries: list[
        DependencyDiscovery
    ] = field(
        default_factory=list,
    )


class FastAPIDependencyParserMixin:
    """
    FastAPI dependency and security extraction capabilities.
    """

    def _discover_function_dependencies(
        self,
        function_node: (
            ast.FunctionDef
            | ast.AsyncFunctionDef
        ),
    ) -> DependencySecuritySummary:
        discoveries: list[
            DependencyDiscovery
        ] = []

        arguments = function_node.args

        positional_arguments = (
            list(arguments.posonlyargs)
            + list(arguments.args)
        )

        positional_defaults: list[
            ast.AST | None
        ] = [
            None
        ] * (
            len(positional_arguments)
            - len(arguments.defaults)
        ) + list(
            arguments.defaults
        )

        for parameter, default_node in zip(
            positional_arguments,
            positional_defaults,
            strict=True,
        ):
            discoveries.extend(
                self._discover_parameter_dependencies(
                    parameter=parameter,
                    default_node=default_node,
                )
            )

        for parameter, default_node in zip(
            arguments.kwonlyargs,
            arguments.kw_defaults,
            strict=True,
        ):
            discoveries.extend(
                self._discover_parameter_dependencies(
                    parameter=parameter,
                    default_node=default_node,
                )
            )

        return self._summarize_dependencies(
            discoveries,
        )

    def _discover_parameter_dependencies(
        self,
        parameter: ast.arg,
        default_node: ast.AST | None,
    ) -> list[DependencyDiscovery]:
        discoveries: list[
            DependencyDiscovery
        ] = []

        if default_node is not None:
            discoveries.extend(
                self._discover_dependencies_in_node(
                    default_node,
                )
            )

        if parameter.annotation is not None:
            discoveries.extend(
                self._discover_dependencies_in_annotation(
                    parameter.annotation,
                )
            )

        return discoveries

    def _discover_dependencies_in_annotation(
        self,
        annotation: ast.AST,
    ) -> list[DependencyDiscovery]:
        if not isinstance(
            annotation,
            ast.Subscript,
        ):
            return []

        annotation_name = (
            self._dependency_qualified_name(
                annotation.value,
            )
            or ""
        )

        if annotation_name.split(".")[-1] != "Annotated":
            return []

        slice_node = annotation.slice

        if isinstance(
            slice_node,
            ast.Tuple,
        ):
            metadata_nodes = list(
                slice_node.elts[1:],
            )
        else:
            metadata_nodes = []

        discoveries: list[
            DependencyDiscovery
        ] = []

        for metadata_node in metadata_nodes:
            discoveries.extend(
                self._discover_dependencies_in_node(
                    metadata_node,
                )
            )

        return discoveries

    def _discover_dependencies_in_node(
        self,
        node: ast.AST,
    ) -> list[DependencyDiscovery]:
        discoveries: list[
            DependencyDiscovery
        ] = []

        for child in ast.walk(
            node,
        ):
            if not isinstance(
                child,
                ast.Call,
            ):
                continue

            discovery = (
                self._parse_dependency_call(
                    child,
                )
            )

            if discovery is not None:
                discoveries.append(
                    discovery,
                )

        return self._deduplicate_dependency_discoveries(
            discoveries,
        )

    def _parse_dependency_call(
        self,
        call: ast.Call,
    ) -> DependencyDiscovery | None:
        callable_name = (
            self._dependency_qualified_name(
                call.func,
            )
            or ""
        )

        declaration_type = (
            callable_name.split(".")[-1]
        )

        if declaration_type not in DEPENDENCY_CALL_NAMES:
            return None

        dependency_node: ast.AST | None = None

        if call.args:
            dependency_node = call.args[0]

        if dependency_node is None:
            dependency_node = (
                self._dependency_keyword_value(
                    call,
                    "dependency",
                )
            )

        dependency_name = (
            self._dependency_expression_text(
                dependency_node,
            )
            if dependency_node is not None
            else None
        )

        expression = (
            self._dependency_expression_text(
                call,
            )
            or declaration_type
        )

        scopes = self._extract_security_scopes(
            call,
        )

        use_cache = (
            self._extract_boolean_keyword(
                call,
                "use_cache",
            )
        )

        security_scheme = (
            self._detect_security_scheme(
                dependency_node,
                dependency_name,
            )
        )

        authentication_required = (
            declaration_type == "Security"
            or security_scheme is not None
            or self._dependency_requires_authentication(
                dependency_name,
            )
        )

        permission_required = (
            bool(scopes)
            or self._dependency_requires_permission(
                dependency_name,
            )
        )

        return DependencyDiscovery(
            expression=expression,
            dependency_name=dependency_name,
            declaration_type=declaration_type,
            security_scheme=security_scheme,
            scopes=scopes,
            authentication_required=(
                authentication_required
            ),
            permission_required=(
                permission_required
            ),
            use_cache=use_cache,
        )

    def _summarize_dependencies(
        self,
        discoveries: Iterable[
            DependencyDiscovery
        ],
    ) -> DependencySecuritySummary:
        unique_discoveries = (
            self._deduplicate_dependency_discoveries(
                list(discoveries),
            )
        )

        dependencies = self._dependency_deduplicate(
            discovery.expression
            for discovery in unique_discoveries
        )

        security_schemes = (
            self._dependency_deduplicate(
                discovery.security_scheme
                for discovery in unique_discoveries
                if discovery.security_scheme
            )
        )

        scopes = self._dependency_deduplicate(
            scope
            for discovery in unique_discoveries
            for scope in discovery.scopes
        )

        return DependencySecuritySummary(
            dependencies=dependencies,
            security_schemes=security_schemes,
            scopes=scopes,
            authentication_required=any(
                discovery.authentication_required
                for discovery in unique_discoveries
            ),
            permission_required=any(
                discovery.permission_required
                for discovery in unique_discoveries
            ),
            discoveries=unique_discoveries,
        )

    @staticmethod
    def _detect_security_scheme(
        dependency_node: ast.AST | None,
        dependency_name: str | None,
    ) -> str | None:
        if dependency_node is None:
            return None

        candidate_names: list[str] = []

        for child in ast.walk(
            dependency_node,
        ):
            if isinstance(
                child,
                (
                    ast.Name,
                    ast.Attribute,
                    ast.Call,
                ),
            ):
                candidate = (
                    FastAPIDependencyParserMixin
                    ._dependency_qualified_name(
                        child.func
                        if isinstance(
                            child,
                            ast.Call,
                        )
                        else child
                    )
                )

                if candidate:
                    candidate_names.append(
                        candidate,
                    )

        if dependency_name:
            candidate_names.append(
                dependency_name,
            )

        for candidate in candidate_names:
            final_name = (
                candidate.split(".")[-1]
            )

            if final_name in SECURITY_CONSTRUCTOR_NAMES:
                return final_name

            normalized = candidate.lower()

            if "oauth2" in normalized:
                return "OAuth2"

            if "httpbearer" in normalized:
                return "HTTPBearer"

            if (
                "apikeyheader" in normalized
                or "api_key_header" in normalized
            ):
                return "APIKeyHeader"

            if (
                "apikeyquery" in normalized
                or "api_key_query" in normalized
            ):
                return "APIKeyQuery"

            if (
                "apikeycookie" in normalized
                or "api_key_cookie" in normalized
            ):
                return "APIKeyCookie"

            if (
                "bearer" in normalized
                or "jwt" in normalized
            ):
                return "Bearer"

            if "basic" in normalized:
                return "HTTPBasic"

            if "openid" in normalized:
                return "OpenIdConnect"

        return None

    @staticmethod
    def _extract_security_scopes(
        call: ast.Call,
    ) -> list[str]:
        scopes_node = (
            FastAPIDependencyParserMixin
            ._dependency_keyword_value(
                call,
                "scopes",
            )
        )

        if not isinstance(
            scopes_node,
            (
                ast.List,
                ast.Tuple,
                ast.Set,
            ),
        ):
            return []

        scopes: list[str] = []

        for scope_node in scopes_node.elts:
            if (
                isinstance(
                    scope_node,
                    ast.Constant,
                )
                and isinstance(
                    scope_node.value,
                    str,
                )
            ):
                scopes.append(
                    scope_node.value,
                )

        return (
            FastAPIDependencyParserMixin
            ._dependency_deduplicate(
                scopes,
            )
        )

    @staticmethod
    def _extract_boolean_keyword(
        call: ast.Call,
        keyword_name: str,
    ) -> bool | None:
        value = (
            FastAPIDependencyParserMixin
            ._dependency_keyword_value(
                call,
                keyword_name,
            )
        )

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

    @staticmethod
    def _dependency_requires_authentication(
        dependency_name: str | None,
    ) -> bool:
        if not dependency_name:
            return False

        normalized = dependency_name.lower()

        return any(
            marker in normalized
            for marker in AUTHENTICATION_MARKERS
        )

    @staticmethod
    def _dependency_requires_permission(
        dependency_name: str | None,
    ) -> bool:
        if not dependency_name:
            return False

        normalized = dependency_name.lower()

        return any(
            marker in normalized
            for marker in PERMISSION_MARKERS
        )

    @staticmethod
    def _dependency_keyword_value(
        call: ast.Call,
        keyword_name: str,
    ) -> ast.AST | None:
        for keyword in call.keywords:
            if keyword.arg == keyword_name:
                return keyword.value

        return None

    @staticmethod
    def _dependency_expression_text(
        node: ast.AST | None,
    ) -> str | None:
        if node is None:
            return None

        try:
            return ast.unparse(
                node,
            )
        except Exception:
            return (
                FastAPIDependencyParserMixin
                ._dependency_qualified_name(
                    node,
                )
            )

    @staticmethod
    def _dependency_qualified_name(
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
                FastAPIDependencyParserMixin
                ._dependency_qualified_name(
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
                FastAPIDependencyParserMixin
                ._dependency_qualified_name(
                    node.value,
                )
            )

        if isinstance(
            node,
            ast.Call,
        ):
            return (
                FastAPIDependencyParserMixin
                ._dependency_qualified_name(
                    node.func,
                )
            )

        return None

    @staticmethod
    def _dependency_deduplicate(
        values: Iterable[str],
    ) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()

        for value in values:
            if not value:
                continue

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
    def _deduplicate_dependency_discoveries(
        discoveries: list[
            DependencyDiscovery
        ],
    ) -> list[DependencyDiscovery]:
        result: list[
            DependencyDiscovery
        ] = []

        seen: set[
            tuple[
                str,
                tuple[str, ...],
            ]
        ] = set()

        for discovery in discoveries:
            identity = (
                discovery.expression,
                tuple(discovery.scopes),
            )

            if identity in seen:
                continue

            seen.add(
                identity,
            )

            result.append(
                discovery,
            )

        return result

    def _summarize_dependency_expressions(
        self,
        dependency_expressions: Iterable[str],
    ) -> DependencySecuritySummary:
        """
        Convert stored dependency expression strings back into
        dependency discoveries without executing analyzed code.
        """

        discoveries: list[
            DependencyDiscovery
        ] = []

        for expression in dependency_expressions:
            if not expression:
                continue

            try:
                expression_tree = ast.parse(
                    expression,
                    mode="eval",
                )
            except SyntaxError:
                authentication_required = (
                    self._dependency_requires_authentication(
                        expression,
                    )
                )

                permission_required = (
                    self._dependency_requires_permission(
                        expression,
                    )
                )

                discoveries.append(
                    DependencyDiscovery(
                        expression=expression,
                        dependency_name=expression,
                        authentication_required=(
                            authentication_required
                        ),
                        permission_required=(
                            permission_required
                        ),
                    )
                )

                continue

            expression_node = (
                expression_tree.body
            )

            if not isinstance(
                expression_node,
                ast.Call,
            ):
                discoveries.append(
                    DependencyDiscovery(
                        expression=expression,
                        dependency_name=expression,
                        authentication_required=(
                            self._dependency_requires_authentication(
                                expression,
                            )
                        ),
                        permission_required=(
                            self._dependency_requires_permission(
                                expression,
                            )
                        ),
                    )
                )

                continue

            discovery = (
                self._parse_dependency_call(
                    expression_node,
                )
            )

            if discovery is None:
                discoveries.append(
                    DependencyDiscovery(
                        expression=expression,
                        dependency_name=(
                            self._dependency_expression_text(
                                expression_node,
                            )
                        ),
                        security_scheme=(
                            self._detect_security_scheme(
                                expression_node,
                                expression,
                            )
                        ),
                        authentication_required=(
                            self._dependency_requires_authentication(
                                expression,
                            )
                        ),
                        permission_required=(
                            self._dependency_requires_permission(
                                expression,
                            )
                        ),
                    )
                )

                continue

            discoveries.append(
                discovery,
            )

        return self._summarize_dependencies(
            discoveries,
        )

    def _merge_dependency_summaries(
        self,
        *summaries: DependencySecuritySummary,
    ) -> DependencySecuritySummary:
        """
        Merge router, decorator and function dependency summaries.
        """

        discoveries: list[
            DependencyDiscovery
        ] = []

        dependencies: list[str] = []
        security_schemes: list[str] = []
        scopes: list[str] = []

        authentication_required = False
        permission_required = False

        for summary in summaries:
            discoveries.extend(
                summary.discoveries,
            )

            dependencies.extend(
                summary.dependencies,
            )

            security_schemes.extend(
                summary.security_schemes,
            )

            scopes.extend(
                summary.scopes,
            )

            authentication_required = (
                authentication_required
                or summary.authentication_required
            )

            permission_required = (
                permission_required
                or summary.permission_required
            )

        unique_discoveries = (
            self._deduplicate_dependency_discoveries(
                discoveries,
            )
        )

        return DependencySecuritySummary(
            dependencies=(
                self._dependency_deduplicate(
                    dependencies,
                )
            ),
            security_schemes=(
                self._dependency_deduplicate(
                    security_schemes,
                )
            ),
            scopes=(
                self._dependency_deduplicate(
                    scopes,
                )
            ),
            authentication_required=(
                authentication_required
            ),
            permission_required=(
                permission_required
            ),
            discoveries=unique_discoveries,
        )

    def _enrich_discovered_endpoint_security(
        self,
        tree: ast.Module,
    ) -> None:
        """
        Populate every discovered endpoint with complete dependency
        and security metadata.

        Sources merged:

        - APIRouter dependencies
        - Route decorator dependencies
        - Endpoint function Depends/Security parameters
        """

        endpoints = list(
            getattr(
                self,
                "endpoints",
                [],
            )
        )

        if not endpoints:
            return

        for node in ast.walk(
            tree,
        ):
            if not isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                ),
            ):
                continue

            route_decorators = []

            for decorator_node in node.decorator_list:
                route_decorator = (
                    self._parse_route_decorator(
                        decorator_node,
                    )
                )

                if route_decorator is not None:
                    route_decorators.append(
                        route_decorator,
                    )

            if not route_decorators:
                continue

            function_summary = (
                self._discover_function_dependencies(
                    node,
                )
            )

            for route_decorator in route_decorators:
                router_definition = (
                    getattr(
                        self,
                        "router_definitions",
                        {},
                    ).get(
                        route_decorator.router_variable,
                    )
                )

                router_prefix = ""

                router_dependencies: list[str] = []

                if router_definition is not None:
                    router_prefix = (
                        router_definition.prefix
                    )

                    router_dependencies = list(
                        router_definition.dependencies
                    )

                full_path = self.join_paths(
                    router_prefix,
                    route_decorator.path,
                )

                endpoint = (
                    self._find_discovered_endpoint(
                        endpoints=endpoints,
                        method=route_decorator.method,
                        full_path=full_path,
                        function_name=node.name,
                    )
                )

                if endpoint is None:
                    continue

                decorator_dependencies = (
                    self._call_expression_list_keyword(
                        route_decorator.raw_node,
                        "dependencies",
                    )
                )

                current_dependencies = list(
                    getattr(
                        endpoint,
                        "dependencies",
                        [],
                    )
                    or []
                )

                stored_summary = (
                    self._summarize_dependency_expressions(
                        [
                            *current_dependencies,
                            *router_dependencies,
                            *decorator_dependencies,
                        ]
                    )
                )

                combined_summary = (
                    self._merge_dependency_summaries(
                        stored_summary,
                        function_summary,
                    )
                )

                endpoint.dependencies = list(
                    combined_summary.dependencies
                )

                endpoint.authentication_required = (
                    bool(
                        getattr(
                            endpoint,
                            "authentication_required",
                            False,
                        )
                    )
                    or combined_summary.authentication_required
                )

                endpoint.permission_required = (
                    bool(
                        getattr(
                            endpoint,
                            "permission_required",
                            False,
                        )
                    )
                    or combined_summary.permission_required
                )

                endpoint.security_schemes = (
                    self._dependency_deduplicate(
                        [
                            *list(
                                getattr(
                                    endpoint,
                                    "security_schemes",
                                    [],
                                )
                                or []
                            ),
                            *combined_summary.security_schemes,
                        ]
                    )
                )

                endpoint.security_scopes = (
                    self._dependency_deduplicate(
                        [
                            *list(
                                getattr(
                                    endpoint,
                                    "security_scopes",
                                    [],
                                )
                                or []
                            ),
                            *combined_summary.scopes,
                        ]
                    )
                )

    @staticmethod
    def _find_discovered_endpoint(
        endpoints: Iterable[object],
        method: str,
        full_path: str,
        function_name: str,
    ) -> object | None:
        normalized_method = method.upper()

        path_matches: list[object] = []

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
                path_matches.append(
                    endpoint,
                )

        if len(path_matches) == 1:
            return path_matches[0]

        for endpoint in path_matches:
            for attribute_name in (
                "function_name",
                "handler_name",
                "endpoint_name",
                "name",
            ):
                endpoint_function_name = (
                    getattr(
                        endpoint,
                        attribute_name,
                        None,
                    )
                )

                if (
                    endpoint_function_name
                    == function_name
                ):
                    return endpoint

        return (
            path_matches[0]
            if path_matches
            else None
        )
