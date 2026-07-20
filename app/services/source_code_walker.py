from __future__ import annotations

import hashlib
import os
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".github",
        ".gitlab",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".next",
        ".nuxt",
        ".output",
        ".parcel-cache",
        ".turbo",
        ".cache",
        ".gradle",
        ".dart_tool",
        ".terraform",
        ".serverless",
        "__pycache__",
        "venv",
        ".venv",
        "env",
        ".env",
        "node_modules",
        "vendor",
        "bower_components",
        "jspm_packages",
        "dist",
        "build",
        "out",
        "target",
        "coverage",
        "htmlcov",
        "site-packages",
        "Pods",
        "DerivedData",
        "bin",
        "obj",
        "logs",
        "tmp",
        "temp",
        "uploads",
        "storage",
    }
)


DEFAULT_IGNORED_FILES = frozenset(
    {
        ".DS_Store",
        "Thumbs.db",
        "desktop.ini",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "composer.lock",
        "poetry.lock",
        "Pipfile.lock",
        "Cargo.lock",
    }
)


LANGUAGE_BY_EXTENSION = {
    ".py": "Python",
    ".pyw": "Python",
    ".js": "JavaScript",
    ".cjs": "JavaScript",
    ".mjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".cts": "TypeScript",
    ".mts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".php": "PHP",
    ".go": "Go",
    ".cs": "C#",
    ".fs": "F#",
    ".fsx": "F#",
    ".dart": "Dart",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".swift": "Swift",
    ".scala": "Scala",
    ".groovy": "Groovy",
    ".c": "C",
    ".h": "C/C++ Header",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++ Header",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "Sass",
    ".less": "Less",
    ".sql": "SQL",
    ".graphql": "GraphQL",
    ".gql": "GraphQL",
    ".proto": "Protocol Buffers",
    ".xml": "XML",
    ".json": "JSON",
    ".jsonc": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".ini": "INI",
    ".cfg": "Configuration",
    ".conf": "Configuration",
    ".properties": "Properties",
    ".env": "Environment",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".ps1": "PowerShell",
    ".bat": "Batch",
    ".cmd": "Batch",
    ".dockerfile": "Dockerfile",
}


SPECIAL_FILE_LANGUAGES = {
    "Dockerfile": "Dockerfile",
    "dockerfile": "Dockerfile",
    "Makefile": "Makefile",
    "makefile": "Makefile",
    "Procfile": "Procfile",
    "Jenkinsfile": "Jenkins",
    "Vagrantfile": "Ruby",
    "Gemfile": "Ruby",
    "Rakefile": "Ruby",
    "Podfile": "Ruby",
    "requirements.txt": "Python Requirements",
    "pyproject.toml": "Python Configuration",
    "Pipfile": "Python Configuration",
    "setup.py": "Python",
    "setup.cfg": "Python Configuration",
    "package.json": "Node.js Manifest",
    "tsconfig.json": "TypeScript Configuration",
    "composer.json": "PHP Manifest",
    "pom.xml": "Maven",
    "build.gradle": "Gradle",
    "build.gradle.kts": "Gradle",
    "settings.gradle": "Gradle",
    "settings.gradle.kts": "Gradle",
    "go.mod": "Go Module",
    "go.sum": "Go Module",
    "Cargo.toml": "Rust Manifest",
    "pubspec.yaml": "Dart Manifest",
    "pubspec.yml": "Dart Manifest",
    "web.config": "ASP.NET Configuration",
    "appsettings.json": "ASP.NET Configuration",
    "openapi.json": "OpenAPI",
    "openapi.yaml": "OpenAPI",
    "openapi.yml": "OpenAPI",
    "swagger.json": "OpenAPI",
    "swagger.yaml": "OpenAPI",
    "swagger.yml": "OpenAPI",
}


SOURCE_CODE_LANGUAGES = frozenset(
    {
        "Python",
        "JavaScript",
        "TypeScript",
        "Java",
        "Kotlin",
        "PHP",
        "Go",
        "C#",
        "F#",
        "Dart",
        "Rust",
        "Ruby",
        "Swift",
        "Scala",
        "Groovy",
        "C",
        "C++",
        "C/C++ Header",
        "C++ Header",
    }
)


@dataclass(frozen=True, slots=True)
class SourceFile:
    absolute_path: str
    relative_path: str
    filename: str
    extension: str
    language: str
    size_bytes: int
    sha256: str
    line_count: int | None
    is_source_code: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SkippedFile:
    relative_path: str
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class SourceWalkResult:
    root_path: str
    files: list[SourceFile]
    skipped_files: list[SkippedFile]
    visited_directories: int
    total_size_bytes: int

    @property
    def total_files(self) -> int:
        return len(self.files)

    @property
    def source_files(self) -> list[SourceFile]:
        return [
            item
            for item in self.files
            if item.is_source_code
        ]

    @property
    def language_counts(self) -> dict[str, int]:
        counts = Counter(
            item.language
            for item in self.files
        )
        return dict(
            sorted(
                counts.items(),
                key=lambda item: (
                    -item[1],
                    item[0].lower(),
                ),
            )
        )

    def to_dict(self) -> dict:
        return {
            "root_path": self.root_path,
            "total_files": self.total_files,
            "source_file_count": len(self.source_files),
            "skipped_file_count": len(self.skipped_files),
            "visited_directories": self.visited_directories,
            "total_size_bytes": self.total_size_bytes,
            "language_counts": self.language_counts,
            "files": [
                item.to_dict()
                for item in self.files
            ],
            "skipped_files": [
                item.to_dict()
                for item in self.skipped_files
            ],
        }


class SourceCodeWalkerError(RuntimeError):
    """Raised when project traversal cannot be completed."""


class SourceCodeWalker:
    def __init__(
        self,
        *,
        ignored_directories: Iterable[str] | None = None,
        ignored_files: Iterable[str] | None = None,
        max_file_size_bytes: int = 5 * 1024 * 1024,
        calculate_line_count: bool = True,
        include_unknown_text_files: bool = False,
    ) -> None:
        if max_file_size_bytes <= 0:
            raise ValueError(
                "max_file_size_bytes must be greater than zero."
            )

        self.ignored_directories = set(
            DEFAULT_IGNORED_DIRECTORIES
        )

        if ignored_directories:
            self.ignored_directories.update(
                ignored_directories
            )

        self.ignored_files = set(
            DEFAULT_IGNORED_FILES
        )

        if ignored_files:
            self.ignored_files.update(
                ignored_files
            )

        self.max_file_size_bytes = max_file_size_bytes
        self.calculate_line_count = calculate_line_count
        self.include_unknown_text_files = (
            include_unknown_text_files
        )

    def walk(
        self,
        root_path: str | Path,
    ) -> SourceWalkResult:
        root = Path(root_path).expanduser().resolve()

        if not root.exists():
            raise SourceCodeWalkerError(
                f"Project path does not exist: {root}"
            )

        if not root.is_dir():
            raise SourceCodeWalkerError(
                f"Project path is not a directory: {root}"
            )

        files: list[SourceFile] = []
        skipped_files: list[SkippedFile] = []
        visited_directories = 0
        total_size_bytes = 0

        try:
            for current_root, directories, filenames in os.walk(
                root,
                topdown=True,
                followlinks=False,
            ):
                visited_directories += 1
                current_path = Path(current_root)

                directories[:] = sorted(
                    directory
                    for directory in directories
                    if not self._should_ignore_directory(
                        current_path / directory,
                        root,
                    )
                )

                for filename in sorted(filenames):
                    file_path = current_path / filename
                    relative_path = self._relative_path(
                        file_path,
                        root,
                    )

                    if file_path.is_symlink():
                        skipped_files.append(
                            SkippedFile(
                                relative_path=relative_path,
                                reason="symbolic_link",
                            )
                        )
                        continue

                    if filename in self.ignored_files:
                        skipped_files.append(
                            SkippedFile(
                                relative_path=relative_path,
                                reason="ignored_filename",
                            )
                        )
                        continue

                    try:
                        file_size = file_path.stat().st_size
                    except OSError:
                        skipped_files.append(
                            SkippedFile(
                                relative_path=relative_path,
                                reason="stat_failed",
                            )
                        )
                        continue

                    if file_size > self.max_file_size_bytes:
                        skipped_files.append(
                            SkippedFile(
                                relative_path=relative_path,
                                reason="file_too_large",
                            )
                        )
                        continue

                    language = self.detect_language(file_path)

                    if language is None:
                        if not self.include_unknown_text_files:
                            skipped_files.append(
                                SkippedFile(
                                    relative_path=relative_path,
                                    reason="unsupported_file_type",
                                )
                            )
                            continue

                        if self._is_binary_file(file_path):
                            skipped_files.append(
                                SkippedFile(
                                    relative_path=relative_path,
                                    reason="binary_file",
                                )
                            )
                            continue

                        language = "Unknown Text"

                    elif self._is_binary_file(file_path):
                        skipped_files.append(
                            SkippedFile(
                                relative_path=relative_path,
                                reason="binary_file",
                            )
                        )
                        continue

                    try:
                        checksum = self._sha256(file_path)
                    except OSError:
                        skipped_files.append(
                            SkippedFile(
                                relative_path=relative_path,
                                reason="read_failed",
                            )
                        )
                        continue

                    line_count = None

                    if self.calculate_line_count:
                        line_count = self._count_lines(file_path)

                    source_file = SourceFile(
                        absolute_path=str(file_path),
                        relative_path=relative_path,
                        filename=filename,
                        extension=file_path.suffix.lower(),
                        language=language,
                        size_bytes=file_size,
                        sha256=checksum,
                        line_count=line_count,
                        is_source_code=(
                            language in SOURCE_CODE_LANGUAGES
                        ),
                    )

                    files.append(source_file)
                    total_size_bytes += file_size

        except OSError as exc:
            raise SourceCodeWalkerError(
                f"Unable to walk project directory: {exc}"
            ) from exc

        files.sort(
            key=lambda item: item.relative_path.lower()
        )

        skipped_files.sort(
            key=lambda item: item.relative_path.lower()
        )

        return SourceWalkResult(
            root_path=str(root),
            files=files,
            skipped_files=skipped_files,
            visited_directories=visited_directories,
            total_size_bytes=total_size_bytes,
        )

    def detect_language(
        self,
        file_path: str | Path,
    ) -> str | None:
        path = Path(file_path)
        filename = path.name

        special_language = SPECIAL_FILE_LANGUAGES.get(
            filename
        )

        if special_language:
            return special_language

        lowered_name = filename.lower()

        for special_name, language in (
            SPECIAL_FILE_LANGUAGES.items()
        ):
            if lowered_name == special_name.lower():
                return language

        if lowered_name.startswith(".env"):
            return "Environment"

        extension = path.suffix.lower()

        return LANGUAGE_BY_EXTENSION.get(extension)

    def _should_ignore_directory(
        self,
        directory_path: Path,
        root: Path,
    ) -> bool:
        directory_name = directory_path.name

        if directory_name in self.ignored_directories:
            return True

        if directory_path.is_symlink():
            return True

        relative_parts = directory_path.relative_to(
            root
        ).parts

        return any(
            part in self.ignored_directories
            for part in relative_parts
        )

    @staticmethod
    def _relative_path(
        file_path: Path,
        root: Path,
    ) -> str:
        return file_path.relative_to(
            root
        ).as_posix()

    @staticmethod
    def _sha256(
        file_path: Path,
    ) -> str:
        digest = hashlib.sha256()

        with file_path.open("rb") as handle:
            for chunk in iter(
                lambda: handle.read(1024 * 1024),
                b"",
            ):
                digest.update(chunk)

        return digest.hexdigest()

    @staticmethod
    def _count_lines(
        file_path: Path,
    ) -> int | None:
        try:
            with file_path.open(
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:
                return sum(1 for _ in handle)
        except OSError:
            return None

    @staticmethod
    def _is_binary_file(
        file_path: Path,
    ) -> bool:
        try:
            with file_path.open("rb") as handle:
                sample = handle.read(8192)
        except OSError:
            return True

        if not sample:
            return False

        if b"\x00" in sample:
            return True

        text_control_characters = {
            7,
            8,
            9,
            10,
            12,
            13,
            27,
        }

        non_text_bytes = sum(
            1
            for byte in sample
            if byte < 32
            and byte not in text_control_characters
        )

        return (
            non_text_bytes / len(sample)
        ) > 0.30


def walk_source_tree(
    root_path: str | Path,
    *,
    ignored_directories: Iterable[str] | None = None,
    ignored_files: Iterable[str] | None = None,
    max_file_size_bytes: int = 5 * 1024 * 1024,
    calculate_line_count: bool = True,
    include_unknown_text_files: bool = False,
) -> SourceWalkResult:
    walker = SourceCodeWalker(
        ignored_directories=ignored_directories,
        ignored_files=ignored_files,
        max_file_size_bytes=max_file_size_bytes,
        calculate_line_count=calculate_line_count,
        include_unknown_text_files=(
            include_unknown_text_files
        ),
    )

    return walker.walk(root_path)
