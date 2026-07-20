from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from app.services.security.source_analysis.context import (
    SourceAnalysisContext,
)
from app.services.security.source_analysis.models import (
    SourceFile,
)


class SourceFileLoader:
    LANGUAGE_BY_SUFFIX: dict[str, str] = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
    }

    def discover(
        self,
        *,
        context: SourceAnalysisContext,
    ) -> tuple[
        list[SourceFile],
        list[str],
        list[str],
    ]:
        source_files: list[SourceFile] = []
        skipped_files: list[str] = []
        errors: list[str] = []

        seen_paths: set[Path] = set()

        for pattern in context.include_patterns:
            for path in context.project_root.glob(
                pattern,
            ):
                resolved_path = path.resolve()

                if resolved_path in seen_paths:
                    continue

                seen_paths.add(
                    resolved_path,
                )

                if not path.is_file():
                    continue

                relative_path = self._relative_path(
                    path=path,
                    context=context,
                )

                if context.is_excluded(
                    path,
                ):
                    skipped_files.append(
                        relative_path,
                    )
                    continue

                try:
                    source_file = self.load(
                        path=path,
                        context=context,
                    )
                except ValueError:
                    skipped_files.append(
                        relative_path,
                    )
                    continue
                except OSError as exc:
                    errors.append(
                        f"{relative_path}: {exc}",
                    )
                    continue
                except UnicodeError as exc:
                    errors.append(
                        f"{relative_path}: {exc}",
                    )
                    continue

                source_files.append(
                    source_file,
                )

        source_files.sort(
            key=lambda item: item.relative_path,
        )

        skipped_files = sorted(
            set(
                skipped_files,
            ),
        )

        errors = sorted(
            set(
                errors,
            ),
        )

        return (
            source_files,
            skipped_files,
            errors,
        )

    def load(
        self,
        *,
        path: Path,
        context: SourceAnalysisContext,
    ) -> SourceFile:
        resolved_path = path.resolve()

        if context.is_excluded(
            resolved_path,
        ):
            raise ValueError(
                "source file is excluded",
            )

        if not resolved_path.is_file():
            raise ValueError(
                "source path is not a file",
            )

        stat = resolved_path.stat()

        if (
            stat.st_size
            > context.max_file_size_bytes
        ):
            raise ValueError(
                "source file exceeds maximum size",
            )

        language = self.detect_language(
            resolved_path,
        )

        if language is None:
            raise ValueError(
                "unsupported source file type",
            )

        content_bytes = resolved_path.read_bytes()

        if b"\x00" in content_bytes:
            raise ValueError(
                "binary source file is not supported",
            )

        content = content_bytes.decode(
            "utf-8",
        )

        relative_path = self._relative_path(
            path=resolved_path,
            context=context,
        )

        return SourceFile(
            path=resolved_path,
            relative_path=relative_path,
            language=language,
            content=content,
            size_bytes=len(
                content_bytes,
            ),
            sha256=sha256(
                content_bytes,
            ).hexdigest(),
        )

    def detect_language(
        self,
        path: Path,
    ) -> str | None:
        return self.LANGUAGE_BY_SUFFIX.get(
            path.suffix.lower(),
        )

    @staticmethod
    def _relative_path(
        *,
        path: Path,
        context: SourceAnalysisContext,
    ) -> str:
        try:
            relative = path.resolve().relative_to(
                context.project_root,
            )
        except ValueError:
            return str(
                path.resolve(),
            )

        return relative.as_posix()
