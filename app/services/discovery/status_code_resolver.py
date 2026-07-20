from __future__ import annotations

import ast
from http import HTTPStatus


HTTP_STATUS_ATTRIBUTE_MAP = {
    name: value.value
    for name, value in HTTPStatus.__members__.items()
}


FASTAPI_STATUS_MAP = {
    f"HTTP_{code}_{name.upper().replace(' ', '_')}": code
    for code, name in (
        (status.value, status.phrase)
        for status in HTTPStatus
    )
}


class StatusCodeResolverMixin:
    """
    Resolves symbolic HTTP status expressions into integer status codes.

    Supports:

    status.HTTP_200_OK
    status.HTTP_201_CREATED
    status.HTTP_204_NO_CONTENT
    status.HTTP_400_BAD_REQUEST
    status.HTTP_401_UNAUTHORIZED
    status.HTTP_403_FORBIDDEN
    status.HTTP_404_NOT_FOUND
    status.HTTP_409_CONFLICT
    status.HTTP_422_UNPROCESSABLE_ENTITY
    HTTPStatus.OK
    HTTPStatus.CREATED
    HTTPStatus.NOT_FOUND
    """

    def resolve_status_code(
        self,
        node: ast.AST | None,
    ) -> int | None:

        if node is None:
            return None

        if isinstance(node, ast.Constant):

            if isinstance(node.value, int):
                return node.value

        if isinstance(node, ast.Attribute):

            return self._resolve_attribute(node)

        return None

    def _resolve_attribute(
        self,
        node: ast.Attribute,
    ) -> int | None:

        try:
            expression = ast.unparse(node)
        except Exception:
            return None

        if expression.startswith("status."):

            symbolic = expression.split(".")[-1]

            return FASTAPI_STATUS_MAP.get(symbolic)

        if expression.startswith("HTTPStatus."):

            symbolic = expression.split(".")[-1]

            return HTTP_STATUS_ATTRIBUTE_MAP.get(symbolic)

        return None
