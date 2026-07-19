from __future__ import annotations

from abc import ABC
from abc import abstractmethod
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from app.services.security.models import (
    SecurityFinding,
)
from app.services.security.remediation.models import (
    RemediationGuidance,
)


@dataclass(slots=True, frozen=True)
class FrameworkContext:
    framework: str | None = None
    language: str | None = None
    project_name: str | None = None
    project_id: int | None = None
    endpoint_method: str | None = None
    endpoint_path: str | None = None
    source_file: str | None = None
    function_name: str | None = None
    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    @property
    def normalized_framework(self) -> str:
        return self.normalize_name(
            self.framework,
        )

    @property
    def normalized_language(self) -> str:
        return self.normalize_name(
            self.language,
        )

    @property
    def endpoint_identifier(self) -> str | None:
        if (
            not self.endpoint_method
            or not self.endpoint_path
        ):
            return None

        return (
            f"{self.endpoint_method.upper()} "
            f"{self.endpoint_path}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "normalized_framework": (
                self.normalized_framework
            ),
            "language": self.language,
            "normalized_language": (
                self.normalized_language
            ),
            "project_name": self.project_name,
            "project_id": self.project_id,
            "endpoint_method": (
                self.endpoint_method.upper()
                if self.endpoint_method
                else None
            ),
            "endpoint_path": self.endpoint_path,
            "endpoint_identifier": (
                self.endpoint_identifier
            ),
            "source_file": self.source_file,
            "function_name": self.function_name,
            "metadata": dict(
                self.metadata,
            ),
        }

    @staticmethod
    def normalize_name(
        value: str | None,
    ) -> str:
        normalized = str(
            value or "",
        ).strip().lower()

        for character in (
            "-",
            "_",
            ".",
            "/",
            "\\",
        ):
            normalized = normalized.replace(
                character,
                " ",
            )

        return " ".join(
            normalized.split()
        )


class FrameworkAdapter(ABC):
    """
    Base contract for framework-specific
    remediation decorators.

    Adapters must preserve the generic guidance
    and only add or refine framework-specific
    implementation details.
    """

    name: str = "base"
    aliases: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    priority: int = 100

    @property
    def normalized_name(self) -> str:
        return FrameworkContext.normalize_name(
            self.name,
        )

    @property
    def normalized_aliases(self) -> tuple[str, ...]:
        values = (
            self.name,
            *self.aliases,
        )

        return tuple(
            dict.fromkeys(
                FrameworkContext.normalize_name(
                    value,
                )
                for value in values
                if FrameworkContext.normalize_name(
                    value,
                )
            )
        )

    @property
    def normalized_languages(
        self,
    ) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                FrameworkContext.normalize_name(
                    value,
                )
                for value in self.languages
                if FrameworkContext.normalize_name(
                    value,
                )
            )
        )

    def supports(
        self,
        context: FrameworkContext,
    ) -> bool:
        framework = (
            context.normalized_framework
        )

        if framework:
            return framework in (
                self.normalized_aliases
            )

        language = context.normalized_language

        if (
            language
            and self.normalized_languages
        ):
            return language in (
                self.normalized_languages
            )

        return False

    @abstractmethod
    def decorate(
        self,
        *,
        finding: SecurityFinding,
        guidance: RemediationGuidance,
        context: FrameworkContext,
    ) -> RemediationGuidance:
        """
        Return framework-aware remediation guidance.

        Implementations must not mutate the supplied
        guidance or finding directly.
        """
        raise NotImplementedError

    def describe(
        self,
    ) -> dict[str, Any]:
        return {
            "name": self.name,
            "aliases": list(
                self.aliases,
            ),
            "languages": list(
                self.languages,
            ),
            "priority": self.priority,
        }
