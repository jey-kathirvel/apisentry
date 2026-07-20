from __future__ import annotations

from app.services.discovery.models import (
    EndpointDiscovery,
    ParameterDiscovery,
)
from app.services.security.models import (
    FindingCategory,
    SecurityConfidence,
    SecurityFinding,
    SecuritySeverity,
    SourceLocation,
)


RISKY_PARAMETER_LOCATIONS = frozenset(
    {
        "body",
        "form",
        "file",
    }
)

VALIDATED_PRIMITIVE_MARKERS = (
    "constr",
    "conint",
    "confloat",
    "condecimal",
    "conlist",
    "conset",
    "conbytes",
    "strictstr",
    "strictint",
    "strictfloat",
    "strictbool",
    "positiveint",
    "negativeint",
    "nonnegativeint",
    "nonpositiveint",
    "emailstr",
    "httpurl",
    "anyurl",
    "ipvanyaddress",
    "ipvanynetwork",
    "ipvanyinterface",
    "uuid",
    "datetime",
    "date",
    "time",
    "decimal",
    "literal[",
    "enum",
    "annotated[",
)

UNVALIDATED_GENERIC_TYPES = frozenset(
    {
        "",
        "any",
        "dict",
        "dict[str,any]",
        "dict[str,object]",
        "mapping",
        "mapping[str,any]",
        "object",
        "request",
        "starlette.requests.request",
        "bytes",
        "bytearray",
        "str",
        "int",
        "float",
        "bool",
        "list",
        "list[any]",
        "list[dict]",
        "list[object]",
        "tuple",
        "set",
    }
)


class ValidationAnalyzer:
    RULE_ID = "VAL-001"

    def analyze(
        self,
        endpoint: EndpointDiscovery,
    ) -> list[SecurityFinding]:
        risky_parameters = [
            parameter
            for parameter in (
                endpoint.parameters or []
            )
            if self._is_risky_parameter(
                parameter
            )
        ]

        if not risky_parameters:
            return []

        method = str(
            endpoint.method or "",
        ).upper()

        path = self._build_endpoint_path(
            endpoint,
        )

        parameter_names = [
            str(
                parameter.name or "",
            )
            for parameter in risky_parameters
        ]

        parameter_locations = [
            str(
                parameter.location or "",
            )
            for parameter in risky_parameters
        ]

        parameter_types = [
            str(
                parameter.python_type or "",
            )
            for parameter in risky_parameters
        ]

        return [
            SecurityFinding(
                rule_id=self.RULE_ID,
                title="Input Validation Missing",
                description=(
                    "The endpoint accepts client-supplied "
                    "input through body, form, or file "
                    "parameters without detectable schema "
                    "or type constraints."
                ),
                category=(
                    FindingCategory.INPUT_VALIDATION
                ),
                severity=SecuritySeverity.MEDIUM,
                confidence=SecurityConfidence.MEDIUM,
                remediation=(
                    "Validate request data with typed "
                    "Pydantic models, constrained fields, "
                    "Annotated validators, explicit length "
                    "and range limits, allowlists, and "
                    "custom validation for business rules."
                ),
                endpoint_method=method,
                endpoint_path=path,
                evidence=(
                    f"{len(risky_parameters)} potentially "
                    "unvalidated request parameter(s) "
                    f"detected: "
                    f"{', '.join(parameter_names)}."
                ),
                owasp_reference="API8:2023",
                cwe_id="CWE-20",
                source_location=SourceLocation(
                    file_path=str(
                        endpoint.file_path or "",
                    ),
                    line_number=endpoint.line_number,
                    function_name=(
                        endpoint.function_name
                    ),
                ),
                metadata={
                    "parameter_count": len(
                        risky_parameters
                    ),
                    "parameter_names": (
                        parameter_names
                    ),
                    "parameter_locations": (
                        parameter_locations
                    ),
                    "parameter_types": (
                        parameter_types
                    ),
                },
            )
        ]

    @classmethod
    def _is_risky_parameter(
        cls,
        parameter: ParameterDiscovery,
    ) -> bool:
        location = cls._normalize(
            parameter.location,
        )

        if location not in RISKY_PARAMETER_LOCATIONS:
            return False

        python_type = cls._normalize(
            parameter.python_type,
        )

        if location == "file":
            return True

        if cls._has_detectable_validation(
            python_type
        ):
            return False

        return True

    @classmethod
    def _has_detectable_validation(
        cls,
        python_type: str,
    ) -> bool:
        if not python_type:
            return False

        if python_type in UNVALIDATED_GENERIC_TYPES:
            return False

        if any(
            marker in python_type
            for marker in VALIDATED_PRIMITIVE_MARKERS
        ):
            return True

        if cls._is_optional_type(
            python_type
        ):
            inner_type = cls._remove_optional(
                python_type
            )

            return cls._has_detectable_validation(
                inner_type
            )

        if cls._looks_like_pydantic_model(
            python_type
        ):
            return True

        return False

    @staticmethod
    def _looks_like_pydantic_model(
        python_type: str,
    ) -> bool:
        if not python_type:
            return False

        container_prefixes = (
            "list[",
            "set[",
            "tuple[",
            "sequence[",
            "dict[",
            "mapping[",
        )

        for prefix in container_prefixes:
            if python_type.startswith(prefix):
                inner = python_type[
                    len(prefix):
                ].rstrip("]")

                if "," in inner:
                    inner = inner.split(
                        ",",
                        1,
                    )[-1]

                return (
                    ValidationAnalyzer
                    ._looks_like_pydantic_model(
                        inner
                    )
                )

        primitive_types = {
            "str",
            "int",
            "float",
            "bool",
            "bytes",
            "bytearray",
            "dict",
            "list",
            "tuple",
            "set",
            "any",
            "object",
            "request",
            "uploadfile",
        }

        base_type = python_type.rsplit(
            ".",
            1,
        )[-1]

        if base_type in primitive_types:
            return False

        if not base_type:
            return False

        model_suffixes = (
            "request",
            "response",
            "schema",
            "model",
            "payload",
            "input",
            "command",
            "dto",
            "data",
            "form",
            "create",
            "update",
        )

        if base_type.endswith(
            model_suffixes
        ):
            return True

        return False

    @staticmethod
    def _is_optional_type(
        python_type: str,
    ) -> bool:
        return (
            python_type.startswith(
                "optional["
            )
            or "|none" in python_type
            or "none|" in python_type
        )

    @staticmethod
    def _remove_optional(
        python_type: str,
    ) -> str:
        normalized = python_type

        if normalized.startswith(
            "optional["
        ):
            normalized = normalized[
                len("optional["):
            ].rstrip("]")

        normalized = normalized.replace(
            "|none",
            "",
        )

        normalized = normalized.replace(
            "none|",
            "",
        )

        return normalized.strip()

    @staticmethod
    def _normalize(
        value: object,
    ) -> str:
        return (
            str(
                value or "",
            )
            .strip()
            .lower()
            .replace(" ", "")
            .replace("typing.", "")
        )

    @staticmethod
    def _build_endpoint_path(
        endpoint: EndpointDiscovery,
    ) -> str:
        prefix = str(
            endpoint.router_prefix or "",
        ).strip()

        route_path = str(
            endpoint.path or "",
        ).strip()

        prefix = prefix.rstrip("/")
        route_path = route_path.lstrip("/")

        if prefix and route_path:
            complete_path = (
                f"{prefix}/{route_path}"
            )
        elif prefix:
            complete_path = prefix
        elif route_path:
            complete_path = (
                f"/{route_path}"
            )
        else:
            complete_path = "/"

        if not complete_path.startswith("/"):
            complete_path = (
                f"/{complete_path}"
            )

        while "//" in complete_path:
            complete_path = (
                complete_path.replace(
                    "//",
                    "/",
                )
            )

        if (
            complete_path != "/"
            and complete_path.endswith("/")
        ):
            complete_path = (
                complete_path.rstrip("/")
            )

        return complete_path
