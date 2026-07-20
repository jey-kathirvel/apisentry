from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from app.services.security.source_analysis import (
    SourceAnalysisContext,
    SourceFileLoader,
)


def write_file(
    path: Path,
    content: str | bytes,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if isinstance(
        content,
        bytes,
    ):
        path.write_bytes(
            content,
        )
        return

    path.write_text(
        content,
        encoding="utf-8",
    )


def test_detect_language() -> None:
    loader = SourceFileLoader()

    assert (
        loader.detect_language(
            Path("app.py"),
        )
        == "python"
    )

    assert (
        loader.detect_language(
            Path("app.js"),
        )
        == "javascript"
    )

    assert (
        loader.detect_language(
            Path("app.jsx"),
        )
        == "javascript"
    )

    assert (
        loader.detect_language(
            Path("app.ts"),
        )
        == "typescript"
    )

    assert (
        loader.detect_language(
            Path("app.tsx"),
        )
        == "typescript"
    )

    assert (
        loader.detect_language(
            Path("App.java"),
        )
        == "java"
    )

    assert (
        loader.detect_language(
            Path("README.md"),
        )
        is None
    )


def test_load_python_file(
    tmp_path: Path,
) -> None:
    source_path = (
        tmp_path
        / "app"
        / "main.py"
    )

    content = (
        "from fastapi import FastAPI\n"
        "\n"
        "app = FastAPI()\n"
    )

    write_file(
        source_path,
        content,
    )

    context = SourceAnalysisContext(
        project_root=tmp_path,
    )

    loader = SourceFileLoader()

    source_file = loader.load(
        path=source_path,
        context=context,
    )

    content_bytes = content.encode(
        "utf-8",
    )

    assert (
        source_file.path
        == source_path.resolve()
    )

    assert (
        source_file.relative_path
        == "app/main.py"
    )

    assert (
        source_file.language
        == "python"
    )

    assert (
        source_file.content
        == content
    )

    assert (
        source_file.size_bytes
        == len(
            content_bytes,
        )
    )

    assert (
        source_file.sha256
        == sha256(
            content_bytes,
        ).hexdigest()
    )


def test_load_rejects_unsupported_file(
    tmp_path: Path,
) -> None:
    source_path = (
        tmp_path
        / "README.md"
    )

    write_file(
        source_path,
        "# Project",
    )

    loader = SourceFileLoader()

    with pytest.raises(
        ValueError,
        match="unsupported",
    ):
        loader.load(
            path=source_path,
            context=SourceAnalysisContext(
                project_root=tmp_path,
            ),
        )


def test_load_rejects_oversized_file(
    tmp_path: Path,
) -> None:
    source_path = (
        tmp_path
        / "large.py"
    )

    write_file(
        source_path,
        "x" * 101,
    )

    context = SourceAnalysisContext(
        project_root=tmp_path,
        max_file_size_bytes=100,
    )

    loader = SourceFileLoader()

    with pytest.raises(
        ValueError,
        match="maximum size",
    ):
        loader.load(
            path=source_path,
            context=context,
        )


def test_load_rejects_binary_file(
    tmp_path: Path,
) -> None:
    source_path = (
        tmp_path
        / "binary.py"
    )

    write_file(
        source_path,
        b"print('safe')\x00binary",
    )

    loader = SourceFileLoader()

    with pytest.raises(
        ValueError,
        match="binary",
    ):
        loader.load(
            path=source_path,
            context=SourceAnalysisContext(
                project_root=tmp_path,
            ),
        )


def test_discover_supported_files(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path / "app/main.py",
        "print('python')\n",
    )

    write_file(
        tmp_path / "web/app.js",
        "console.log('javascript');\n",
    )

    write_file(
        tmp_path / "web/component.tsx",
        "export default function App() {}\n",
    )

    write_file(
        tmp_path / "src/App.java",
        "class App {}\n",
    )

    write_file(
        tmp_path / "README.md",
        "# Project\n",
    )

    loader = SourceFileLoader()

    files, skipped, errors = loader.discover(
        context=SourceAnalysisContext(
            project_root=tmp_path,
        ),
    )

    assert [
        source_file.relative_path
        for source_file in files
    ] == [
        "app/main.py",
        "src/App.java",
        "web/app.js",
        "web/component.tsx",
    ]

    assert skipped == []
    assert errors == []


def test_discover_excludes_directories(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path / "app/main.py",
        "print('included')\n",
    )

    write_file(
        tmp_path / "venv/lib/package.py",
        "print('excluded')\n",
    )

    write_file(
        tmp_path / "node_modules/pkg/index.js",
        "console.log('excluded');\n",
    )

    write_file(
        tmp_path / ".git/hooks/test.py",
        "print('excluded')\n",
    )

    loader = SourceFileLoader()

    files, skipped, errors = loader.discover(
        context=SourceAnalysisContext(
            project_root=tmp_path,
        ),
    )

    assert [
        source_file.relative_path
        for source_file in files
    ] == [
        "app/main.py",
    ]

    assert skipped == [
        ".git/hooks/test.py",
        "node_modules/pkg/index.js",
        "venv/lib/package.py",
    ]

    assert errors == []


def test_discover_skips_oversized_files(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path / "small.py",
        "print('small')\n",
    )

    write_file(
        tmp_path / "large.py",
        "x" * 101,
    )

    loader = SourceFileLoader()

    files, skipped, errors = loader.discover(
        context=SourceAnalysisContext(
            project_root=tmp_path,
            max_file_size_bytes=100,
        ),
    )

    assert [
        source_file.relative_path
        for source_file in files
    ] == [
        "small.py",
    ]

    assert skipped == [
        "large.py",
    ]

    assert errors == []


def test_discover_removes_duplicate_matches(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path / "app/main.py",
        "print('hello')\n",
    )

    context = SourceAnalysisContext(
        project_root=tmp_path,
        include_patterns=(
            "**/*.py",
            "app/*.py",
        ),
    )

    loader = SourceFileLoader()

    files, skipped, errors = loader.discover(
        context=context,
    )

    assert len(
        files,
    ) == 1

    assert (
        files[0].relative_path
        == "app/main.py"
    )

    assert skipped == []
    assert errors == []
