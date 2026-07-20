"""
API Sentry
Discovery Domain Models


if TYPE_CHECKING:
    from app.services.discovery.response_parser import ResponseDiscovery
Shared immutable-style data structures used by
framework-specific source-code discovery engines.
"""

from __future__ import annotations

import ast

from dataclasses import dataclass
from dataclasses import field
from typing import TYPE_CHECKING


def join_paths(
    prefix: str,
    path: str,
) -> str:
    """
    Join a router prefix and endpoint path into one normalized path.
    """

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


@dataclass(slots=True)
class RouteDecorator:
    method: str
    path: str
    router_variable: str
    raw_node: ast.Call


@dataclass(slots=True)
class RouterDefinition:
    variable_name: str

    prefix: str = ""

    tags: list[str] = field(
        default_factory=list,
    )

    dependencies: list[str] = field(
        default_factory=list,
    )


@dataclass(slots=True)
class ParameterDiscovery:
    """
    Represents one FastAPI endpoint parameter.
    """

    name: str

    location: str

    python_type: str | None = None

    required: bool = True

    default_value: str | None = None

    description: str | None = None

    alias: str | None = None

    example: str | None = None

    deprecated: bool = False

    nullable: bool = False


@dataclass(slots=True)
class EndpointDiscovery:
    method: str

    path: str

    router_prefix: str

    function_name: str

    file_path: str

    line_number: int

    router_variable: str

    tags: list[str] = field(
        default_factory=list,
    )

    summary: str | None = None

    description: str | None = None

    deprecated: bool = False

    response_model: str | None = None

    status_code: int | None = None

    response_class: str | None = None

    operation_id: str | None = None

    dependencies: list[str] = field(
        default_factory=list,
    )

    parameters: list[ParameterDiscovery] = field(
        default_factory=list,
    )

    authentication_required: bool = False

    @property
    def full_path(self) -> str:
        return join_paths(
            self.router_prefix,
            self.path,
        )
    permission_required: bool = False
    security_schemes: list[str] = field(
        default_factory=list,
    )
    security_scopes: list[str] = field(
        default_factory=list,
    )
    default_status_code: int | None = None
    responses: list[ResponseDiscovery] = field(
        default_factory=list,
    )
