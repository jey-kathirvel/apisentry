from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from pathlib import Path
from typing import Any


class SourceIssueSeverity(
    str,
    Enum,
):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceIssueConfidence(
    str,
    Enum,
):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(
    slots=True,
    frozen=True,
)
class SourceLocation:
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    function_name: str | None = None
    class_name: str | None = None

    def __post_init__(
        self,
    ) -> None:
        if not self.file_path.strip():
            raise ValueError(
                "file_path cannot be empty",
            )

        for field_name in (
            "line_start",
            "line_end",
            "column_start",
            "column_end",
        ):
            value = getattr(
                self,
                field_name,
            )

            if (
                value is not None
                and value < 1
            ):
                raise ValueError(
                    f"{field_name} must be greater than zero",
                )

        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise ValueError(
                "line_end cannot be before line_start",
            )

    @property
    def display_name(
        self,
    ) -> str:
        if self.line_start is None:
            return self.file_path

        if (
            self.line_end is None
            or self.line_end == self.line_start
        ):
            return (
                f"{self.file_path}:"
                f"{self.line_start}"
            )

        return (
            f"{self.file_path}:"
            f"{self.line_start}-"
            f"{self.line_end}"
        )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "column_start": self.column_start,
            "column_end": self.column_end,
            "function_name": self.function_name,
            "class_name": self.class_name,
            "display_name": self.display_name,
        }


@dataclass(
    slots=True,
)
class SourceIssue:
    rule_id: str
    title: str
    description: str
    category: str
    severity: SourceIssueSeverity
    confidence: SourceIssueConfidence
    remediation: str
    location: SourceLocation

    evidence: str | None = None
    cwe_id: str | None = None
    owasp_reference: str | None = None
    endpoint_method: str | None = None
    endpoint_path: str | None = None
    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    def __post_init__(
        self,
    ) -> None:
        for field_name in (
            "rule_id",
            "title",
            "description",
            "category",
            "remediation",
        ):
            value = getattr(
                self,
                field_name,
            )

            if not value.strip():
                raise ValueError(
                    f"{field_name} cannot be empty",
                )

        self.rule_id = (
            self.rule_id
            .strip()
            .upper()
        )

        self.category = (
            self.category
            .strip()
            .lower()
        )

        if self.endpoint_method:
            self.endpoint_method = (
                self.endpoint_method
                .strip()
                .upper()
            )

        if self.endpoint_path:
            self.endpoint_path = (
                self.endpoint_path
                .strip()
            )

    @property
    def fingerprint(
        self,
    ) -> str:
        parts = [
            self.rule_id,
            self.location.file_path,
            str(
                self.location.line_start
                or 0
            ),
            self.endpoint_method or "",
            self.endpoint_path or "",
        ]

        return "|".join(
            parts,
        )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "remediation": self.remediation,
            "location": self.location.to_dict(),
            "evidence": self.evidence,
            "cwe_id": self.cwe_id,
            "owasp_reference": self.owasp_reference,
            "endpoint_method": self.endpoint_method,
            "endpoint_path": self.endpoint_path,
            "metadata": dict(
                self.metadata,
            ),
            "fingerprint": self.fingerprint,
        }


@dataclass(
    slots=True,
    frozen=True,
)
class SourceFile:
    path: Path
    relative_path: str
    language: str
    content: str
    size_bytes: int
    sha256: str

    def __post_init__(
        self,
    ) -> None:
        if not self.relative_path.strip():
            raise ValueError(
                "relative_path cannot be empty",
            )

        if not self.language.strip():
            raise ValueError(
                "language cannot be empty",
            )

        if self.size_bytes < 0:
            raise ValueError(
                "size_bytes cannot be negative",
            )

        if not self.sha256.strip():
            raise ValueError(
                "sha256 cannot be empty",
            )

    @property
    def lines(
        self,
    ) -> tuple[str, ...]:
        return tuple(
            self.content.splitlines(),
        )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return {
            "path": str(
                self.path,
            ),
            "relative_path": self.relative_path,
            "language": self.language,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "line_count": len(
                self.lines,
            ),
        }


@dataclass(
    slots=True,
)
class SourceAnalysisResult:
    analyzer: str
    files_scanned: int
    issues: list[SourceIssue] = field(
        default_factory=list,
    )
    skipped_files: list[str] = field(
        default_factory=list,
    )
    errors: list[str] = field(
        default_factory=list,
    )
    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    def __post_init__(
        self,
    ) -> None:
        if not self.analyzer.strip():
            raise ValueError(
                "analyzer cannot be empty",
            )

        if self.files_scanned < 0:
            raise ValueError(
                "files_scanned cannot be negative",
            )

    @property
    def issue_count(
        self,
    ) -> int:
        return len(
            self.issues,
        )

    @property
    def successful(
        self,
    ) -> bool:
        return not self.errors

    def deduplicate(
        self,
    ) -> SourceAnalysisResult:
        unique: dict[
            str,
            SourceIssue,
        ] = {}

        for issue in self.issues:
            unique.setdefault(
                issue.fingerprint,
                issue,
            )

        self.issues = list(
            unique.values(),
        )

        return self

    def to_dict(
        self,
    ) -> dict[str, Any]:
        return {
            "analyzer": self.analyzer,
            "files_scanned": self.files_scanned,
            "issue_count": self.issue_count,
            "successful": self.successful,
            "issues": [
                issue.to_dict()
                for issue in self.issues
            ],
            "skipped_files": list(
                self.skipped_files,
            ),
            "errors": list(
                self.errors,
            ),
            "metadata": dict(
                self.metadata,
            ),
        }
