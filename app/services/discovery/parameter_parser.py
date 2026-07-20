"""
API Sentry
FastAPI Parameter Parser

Static AST-based extraction of FastAPI endpoint parameters.

This parser never imports or executes analyzed application code.
"""

from __future__ import annotations

import ast

from app.services.discovery.models import ParameterDiscovery


class FastAPIParameterParserMixin:
    """
    Parameter-discovery capabilities for FastAPI AST analyzers.
    """

    def _discover_parameters(
        self,
        function_node: ast.FunctionDef | ast.AsyncFunctionDef,
        route_path: str = "",
    ) -> list[ParameterDiscovery]:
        discovered: list[
            ParameterDiscovery
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
            if parameter.arg in {
                "self",
                "cls",
            }:
                continue

            discovered.append(
                self._build_parameter_discovery(
                    parameter=parameter,
                    default_node=default_node,
                    route_path=route_path,
                    fallback_location="unknown",
                )
            )

        if arguments.vararg is not None:
            discovered.append(
                ParameterDiscovery(
                    name=arguments.vararg.arg,
                    location="vararg",
                    python_type=self._annotation_text(
                        arguments.vararg.annotation,
                    ),
                    required=False,
                )
            )

        for parameter, default_node in zip(
            arguments.kwonlyargs,
            arguments.kw_defaults,
            strict=True,
        ):
            discovered.append(
                self._build_parameter_discovery(
                    parameter=parameter,
                    default_node=default_node,
                    route_path=route_path,
                    fallback_location="keyword",
                )
            )

        if arguments.kwarg is not None:
            discovered.append(
                ParameterDiscovery(
                    name=arguments.kwarg.arg,
                    location="kwargs",
                    python_type=self._annotation_text(
                        arguments.kwarg.annotation,
                    ),
                    required=False,
                )
            )

        return discovered

    def _build_parameter_discovery(
        self,
        parameter: ast.arg,
        default_node: ast.AST | None,
        route_path: str,
        fallback_location: str,
    ) -> ParameterDiscovery:
        annotation_node = parameter.annotation

        base_annotation, annotated_metadata = (
            self._unwrap_annotated_annotation(
                annotation_node,
            )
        )

        parameter_call = self._fastapi_parameter_call(
            default_node,
        )

        if parameter_call is None:
            for metadata_node in annotated_metadata:
                parameter_call = (
                    self._fastapi_parameter_call(
                        metadata_node,
                    )
                )

                if parameter_call is not None:
                    break

        location = fallback_location

        if parameter_call is not None:
            location = self._fastapi_parameter_location(
                parameter_call,
            )

        elif self._annotation_is_upload_file(
            base_annotation,
        ):
            location = "file"

        elif self._route_contains_parameter(
            route_path,
            parameter.arg,
        ):
            location = "path"

        required = self._parameter_required(
            default_node=default_node,
            parameter_call=parameter_call,
            location=location,
        )

        default_value = self._parameter_default_value(
            default_node=default_node,
            parameter_call=parameter_call,
        )

        nullable = (
            self._annotation_is_nullable(
                base_annotation,
            )
            or self._node_is_none(
                default_node,
            )
            or (
                parameter_call is not None
                and self._call_first_argument_is_none(
                    parameter_call,
                )
            )
        )

        description = None
        alias = None
        example = None
        deprecated = False

        if parameter_call is not None:
            description = self._call_string_keyword_local(
                parameter_call,
                "description",
            )

            alias = self._call_string_keyword_local(
                parameter_call,
                "alias",
            )

            example = self._parameter_example(
                parameter_call,
            )

            deprecated = (
                self._call_boolean_keyword_local(
                    parameter_call,
                    "deprecated",
                )
                or False
            )

        return ParameterDiscovery(
            name=parameter.arg,
            location=location,
            python_type=self._annotation_text(
                base_annotation,
            ),
            required=required,
            default_value=default_value,
            description=description,
            alias=alias,
            example=example,
            deprecated=deprecated,
            nullable=nullable,
        )

    @staticmethod
    def _unwrap_annotated_annotation(
        annotation: ast.AST | None,
    ) -> tuple[
        ast.AST | None,
        list[ast.AST],
    ]:
        if not isinstance(
            annotation,
            ast.Subscript,
        ):
            return annotation, []

        annotation_name = (
            FastAPIParameterParserMixin._qualified_name_local(
                annotation.value,
            )
        )

        if not annotation_name:
            return annotation, []

        if annotation_name.split(".")[-1] != "Annotated":
            return annotation, []

        slice_node = annotation.slice

        if isinstance(
            slice_node,
            ast.Tuple,
        ):
            elements = list(
                slice_node.elts
            )
        else:
            elements = [
                slice_node,
            ]

        if not elements:
            return annotation, []

        return (
            elements[0],
            elements[1:],
        )

    @staticmethod
    def _fastapi_parameter_call(
        node: ast.AST | None,
    ) -> ast.Call | None:
        if not isinstance(
            node,
            ast.Call,
        ):
            return None

        callable_name = (
            FastAPIParameterParserMixin._qualified_name_local(
                node.func,
            )
        )

        if not callable_name:
            return None

        supported_names = {
            "Path",
            "Query",
            "Body",
            "Form",
            "File",
            "Header",
            "Cookie",
        }

        if callable_name.split(".")[-1] not in supported_names:
            return None

        return node

    @staticmethod
    def _fastapi_parameter_location(
        parameter_call: ast.Call,
    ) -> str:
        callable_name = (
            FastAPIParameterParserMixin._qualified_name_local(
                parameter_call.func,
            )
            or ""
        )

        location_map = {
            "Path": "path",
            "Query": "query",
            "Body": "body",
            "Form": "form",
            "File": "file",
            "Header": "header",
            "Cookie": "cookie",
        }

        return location_map.get(
            callable_name.split(".")[-1],
            "unknown",
        )

    @staticmethod
    def _annotation_is_upload_file(
        annotation: ast.AST | None,
    ) -> bool:
        if annotation is None:
            return False

        for node in ast.walk(
            annotation,
        ):
            qualified_name = (
                FastAPIParameterParserMixin._qualified_name_local(
                    node,
                )
            )

            if not qualified_name:
                continue

            if qualified_name.split(".")[-1] == "UploadFile":
                return True

        return False

    @staticmethod
    def _route_contains_parameter(
        route_path: str,
        parameter_name: str,
    ) -> bool:
        expected_prefix = (
            "{" + parameter_name
        )

        for segment in route_path.split(
            "/"
        ):
            if (
                segment.startswith(
                    expected_prefix,
                )
                and segment.endswith(
                    "}",
                )
            ):
                return True

        return False

    @staticmethod
    def _parameter_required(
        default_node: ast.AST | None,
        parameter_call: ast.Call | None,
        location: str,
    ) -> bool:
        if location == "path":
            return True

        if parameter_call is not None:
            if parameter_call.args:
                first_argument = (
                    parameter_call.args[0]
                )

                if FastAPIParameterParserMixin._node_is_ellipsis(
                    first_argument,
                ):
                    return True

                return False

            return default_node is None

        return default_node is None

    @staticmethod
    def _parameter_default_value(
        default_node: ast.AST | None,
        parameter_call: ast.Call | None,
    ) -> str | None:
        if parameter_call is not None:
            if parameter_call.args:
                first_argument = (
                    parameter_call.args[0]
                )

                if FastAPIParameterParserMixin._node_is_ellipsis(
                    first_argument,
                ):
                    return None

                return (
                    FastAPIParameterParserMixin._expression_text_local(
                        first_argument,
                    )
                )

            if default_node is not None:
                return (
                    FastAPIParameterParserMixin._expression_text_local(
                        default_node,
                    )
                )

            return None

        if default_node is None:
            return None

        return FastAPIParameterParserMixin._expression_text_local(
            default_node,
        )

    @staticmethod
    def _annotation_is_nullable(
        annotation: ast.AST | None,
    ) -> bool:
        if annotation is None:
            return False

        if (
            isinstance(
                annotation,
                ast.BinOp,
            )
            and isinstance(
                annotation.op,
                ast.BitOr,
            )
        ):
            return (
                FastAPIParameterParserMixin._annotation_is_nullable(
                    annotation.left,
                )
                or FastAPIParameterParserMixin._annotation_is_nullable(
                    annotation.right,
                )
            )

        if (
            isinstance(
                annotation,
                ast.Constant,
            )
            and annotation.value is None
        ):
            return True

        if (
            isinstance(
                annotation,
                ast.Name,
            )
            and annotation.id in {
                "None",
                "NoneType",
            }
        ):
            return True

        if isinstance(
            annotation,
            ast.Subscript,
        ):
            annotation_name = (
                FastAPIParameterParserMixin._qualified_name_local(
                    annotation.value,
                )
                or ""
            )

            final_name = annotation_name.split(
                "."
            )[-1]

            if final_name == "Optional":
                return True

            if final_name == "Union":
                if isinstance(
                    annotation.slice,
                    ast.Tuple,
                ):
                    elements = list(
                        annotation.slice.elts
                    )
                else:
                    elements = [
                        annotation.slice,
                    ]

                return any(
                    FastAPIParameterParserMixin._annotation_is_nullable(
                        element,
                    )
                    for element in elements
                )

        return False

    @staticmethod
    def _node_is_ellipsis(
        node: ast.AST | None,
    ) -> bool:
        return (
            isinstance(
                node,
                ast.Constant,
            )
            and node.value is Ellipsis
        )

    @staticmethod
    def _node_is_none(
        node: ast.AST | None,
    ) -> bool:
        return (
            isinstance(
                node,
                ast.Constant,
            )
            and node.value is None
        )

    @staticmethod
    def _call_first_argument_is_none(
        call: ast.Call,
    ) -> bool:
        if not call.args:
            return False

        return FastAPIParameterParserMixin._node_is_none(
            call.args[0],
        )

    @staticmethod
    def _parameter_example(
        parameter_call: ast.Call,
    ) -> str | None:
        for keyword_name in (
            "example",
            "examples",
            "openapi_examples",
        ):
            value = (
                FastAPIParameterParserMixin._keyword_value_local(
                    parameter_call,
                    keyword_name,
                )
            )

            if value is None:
                continue

            return (
                FastAPIParameterParserMixin._expression_text_local(
                    value,
                )
            )

        return None

    @staticmethod
    def _annotation_text(
        annotation: ast.AST | None,
    ) -> str | None:
        if annotation is None:
            return None

        return FastAPIParameterParserMixin._expression_text_local(
            annotation,
        )

    @staticmethod
    def _qualified_name_local(
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
                FastAPIParameterParserMixin._qualified_name_local(
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
                FastAPIParameterParserMixin._qualified_name_local(
                    node.value,
                )
            )

        return None

    @staticmethod
    def _keyword_value_local(
        call: ast.Call,
        keyword_name: str,
    ) -> ast.AST | None:
        for keyword in call.keywords:
            if keyword.arg == keyword_name:
                return keyword.value

        return None

    @staticmethod
    def _call_string_keyword_local(
        call: ast.Call,
        keyword_name: str,
    ) -> str | None:
        value = (
            FastAPIParameterParserMixin._keyword_value_local(
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
                str,
            )
        ):
            return value.value

        return None

    @staticmethod
    def _call_boolean_keyword_local(
        call: ast.Call,
        keyword_name: str,
    ) -> bool | None:
        value = (
            FastAPIParameterParserMixin._keyword_value_local(
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
    def _expression_text_local(
        node: ast.AST,
    ) -> str | None:
        try:
            return ast.unparse(
                node,
            )
        except Exception:
            return (
                FastAPIParameterParserMixin._qualified_name_local(
                    node,
                )
            )
