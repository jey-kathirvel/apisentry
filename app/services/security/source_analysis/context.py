from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Any


@dataclass(
    slots=True,
    frozen=True,
)
class SourceAnalysisContext:
    project_root: Path
    project_id: int | None = None
    project_name: str | None = None
    framework: str | None = None
    language: str | None = None

    include_patterns: tuple[str, ...] = (
        "**/*.py",
        "**/*.js",
        "**/*.jsx",
        "**/*.ts",
        "**/*.tsx",
        "**/*.java",
    )

    exclude_directories: tuple[str, ...] = (
        ".git",
        ".idea",
        ".vscode",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "venv",
        ".venv",
        "env",
        "node_modules",
        "dist",
        "build",
        "coverage",
        "htmlcov",
        "migrations",
    )

    max_file_size_bytes: int = (
        2 * 1024 * 1024
    )

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    def __post_init__(
        self,
    ) -> None:
        object.__setattr__(
            self,
            "project_root",
            self.project_root.resolve(),
        )

        if self.max_file_size_bytes < 1:
            raise ValueError(
                "max_file_size_bytes must be greater than zero",
            )

    @property
    def normalized_framework(
        self,
    ) -> str:
        return (
            self.framework
            or ""
        ).strip().lower()

    @property
    def normalized_language(
        self,
    ) -> str:
        return (
            self.language
            or ""
        ).strip().lower()

    def is_excluded(
        self,
        path: Path,
    ) -> bool:
        try:
            relative = path.resolve().relative_to(
                self.project_root,
            )
        except ValueError:
            return True

        return any(
            part in self.exclude_directories
            for part in relative.parts
        )
