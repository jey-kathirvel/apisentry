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


FILE_LOCATIONS = frozenset(
    {
        "file",
        "files",
        "upload",
    }
)

FILE_PYTHON_TYPES = frozenset(
    {
        "uploadfile",
        "fastapi.uploadfile",
        "bytes",
        "list[uploadfile]",
        "list[fastapi.uploadfile]",
        "sequence[uploadfile]",
        "tuple[uploadfile]",
    }
)


class FileUploadAnalyzer:
    """
    Detect endpoints accepting uploaded files without
    observable file-security validation.

    FILE-001:
        Potentially insecure file upload.
    """

    RULE_ID = "FILE-001"

    def analyze(
        self,
        endpoint: EndpointDiscovery,
    ) -> list[SecurityFinding]:
        upload_parameters = [
            parameter
            for parameter in (
                endpoint.parameters or []
            )
            if self._is_upload_parameter(
                parameter
            )
        ]

        if not upload_parameters:
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
            for parameter in upload_parameters
        ]

        parameter_types = [
            str(
                parameter.python_type or "",
            )
            for parameter in upload_parameters
        ]

        parameter_locations = [
            str(
                parameter.location or "",
            )
            for parameter in upload_parameters
        ]

        return [
            SecurityFinding(
                rule_id=self.RULE_ID,
                title=(
                    "Potentially Insecure File Upload"
                ),
                description=(
                    "The endpoint accepts uploaded files, "
                    "but no detectable validation for file "
                    "size, extension, MIME type, filename, "
                    "or storage destination was discovered."
                ),
                category=FindingCategory.FILE_UPLOAD,
                severity=SecuritySeverity.HIGH,
                confidence=SecurityConfidence.MEDIUM,
                remediation=(
                    "Allow only approved file extensions "
                    "and MIME types, enforce a maximum file "
                    "size, generate server-side filenames, "
                    "store uploads outside executable web "
                    "paths, and scan untrusted content "
                    "before processing it."
                ),
                endpoint_method=method,
                endpoint_path=path,
                evidence=(
                    f"{len(upload_parameters)} upload "
                    "parameter(s) detected: "
                    f"{', '.join(parameter_names)}."
                ),
                owasp_reference="API8:2023",
                cwe_id="CWE-434",
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
                    "upload_parameter_count": len(
                        upload_parameters
                    ),
                    "upload_parameter_names": (
                        parameter_names
                    ),
                    "upload_parameter_types": (
                        parameter_types
                    ),
                    "upload_parameter_locations": (
                        parameter_locations
                    ),
                },
            )
        ]

    @classmethod
    def _is_upload_parameter(
        cls,
        parameter: ParameterDiscovery,
    ) -> bool:
        location = cls._normalize(
            parameter.location,
        )

        python_type = cls._normalize(
            parameter.python_type,
        )

        name = cls._normalize(
            parameter.name,
        )

        if location in FILE_LOCATIONS:
            return True

        if python_type in FILE_PYTHON_TYPES:
            return True

        if "uploadfile" in python_type:
            return True

        if (
            location == "form"
            and cls._looks_like_file_type(
                python_type
            )
        ):
            return True

        if (
            location in {
                "form",
                "body",
            }
            and name in {
                "file",
                "files",
                "upload",
                "attachment",
                "attachments",
            }
            and cls._looks_like_file_type(
                python_type
            )
        ):
            return True

        return False

    @staticmethod
    def _looks_like_file_type(
        python_type: str,
    ) -> bool:
        if not python_type:
            return False

        file_markers = (
            "uploadfile",
            "bytes",
            "binaryio",
            "io.bytesio",
            "starlette.datastructures.uploadfile",
        )

        return any(
            marker in python_type
            for marker in file_markers
        )

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
