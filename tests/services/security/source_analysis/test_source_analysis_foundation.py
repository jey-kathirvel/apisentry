from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from app.services.security.source_analysis import (
    SourceAnalysisContext,
    SourceAnalysisResult,
    SourceAnalyzer,
    SourceAnalyzerRegistry,
    SourceFile,
    SourceIssue,
    SourceIssueConfidence,
    SourceIssueSeverity,
    SourceLocation,
)


class PythonAnalyzer(
    SourceAnalyzer,
):
    name = "python-security"
    languages = (
        "python",
    )
    priority = 10

    def analyze(
        self,
        *,
        files: list[SourceFile],
        context: SourceAnalysisContext,
    ) -> SourceAnalysisResult:
        return SourceAnalysisResult(
            analyzer=self.name,
            files_scanned=len(
                files,
            ),
        )


class FastAPIAnalyzer(
    SourceAnalyzer,
):
    name = "fastapi-security"
    languages = (
        "python",
    )
    frameworks = (
        "fastapi",
    )
    priority = 20

    def analyze(
        self,
        *,
        files: list[SourceFile],
        context: SourceAnalysisContext,
    ) -> SourceAnalysisResult:
        return SourceAnalysisResult(
            analyzer=self.name,
            files_scanned=len(
                files,
            ),
        )


def build_source_file() -> SourceFile:
    content = "print('hello')\n"

    return SourceFile(
        path=Path(
            "/tmp/project/app.py",
        ),
        relative_path="app.py",
        language="python",
        content=content,
        size_bytes=len(
            content.encode(),
        ),
        sha256=sha256(
            content.encode(),
        ).hexdigest(),
    )


def test_source_location_display_name() -> None:
    location = SourceLocation(
        file_path="app/main.py",
        line_start=10,
        line_end=12,
    )

    assert (
        location.display_name
        == "app/main.py:10-12"
    )


def test_source_location_rejects_invalid_range() -> None:
    with pytest.raises(
        ValueError,
    ):
        SourceLocation(
            file_path="app/main.py",
            line_start=12,
            line_end=10,
        )


def test_source_issue_normalization_and_fingerprint() -> None:
    issue = SourceIssue(
        rule_id=" src-001 ",
        title="Unsafe call",
        description="Unsafe call detected.",
        category=" Injection ",
        severity=SourceIssueSeverity.HIGH,
        confidence=SourceIssueConfidence.HIGH,
        remediation="Remove unsafe call.",
        location=SourceLocation(
            file_path="app/main.py",
            line_start=20,
        ),
        endpoint_method=" post ",
        endpoint_path=" /users ",
    )

    assert issue.rule_id == "SRC-001"
    assert issue.category == "injection"
    assert issue.endpoint_method == "POST"
    assert issue.endpoint_path == "/users"

    assert (
        issue.fingerprint
        == "SRC-001|app/main.py|20|POST|/users"
    )


def test_result_deduplicates_issues() -> None:
    issue = SourceIssue(
        rule_id="SRC-001",
        title="Unsafe call",
        description="Unsafe call detected.",
        category="injection",
        severity=SourceIssueSeverity.HIGH,
        confidence=SourceIssueConfidence.HIGH,
        remediation="Remove unsafe call.",
        location=SourceLocation(
            file_path="app/main.py",
            line_start=20,
        ),
    )

    result = SourceAnalysisResult(
        analyzer="test",
        files_scanned=1,
        issues=[
            issue,
            issue,
        ],
    )

    result.deduplicate()

    assert result.issue_count == 1
    assert result.successful is True


def test_context_exclusion(tmp_path: Path) -> None:
    excluded = (
        tmp_path
        / "node_modules"
        / "package.js"
    )

    included = (
        tmp_path
        / "app"
        / "main.py"
    )

    context = SourceAnalysisContext(
        project_root=tmp_path,
    )

    assert context.is_excluded(
        excluded,
    ) is True

    assert context.is_excluded(
        included,
    ) is False


def test_registry_resolves_by_framework_and_language(
    tmp_path: Path,
) -> None:
    registry = SourceAnalyzerRegistry(
        [
            PythonAnalyzer(),
            FastAPIAnalyzer(),
        ],
    )

    context = SourceAnalysisContext(
        project_root=tmp_path,
        framework="FastAPI",
        language="Python",
    )

    resolved = registry.resolve(
        context=context,
        source_file=build_source_file(),
    )

    assert [
        analyzer.name
        for analyzer in resolved
    ] == [
        "fastapi-security",
        "python-security",
    ]


def test_registry_duplicate_protection() -> None:
    registry = SourceAnalyzerRegistry()

    registry.register(
        PythonAnalyzer(),
    )

    with pytest.raises(
        ValueError,
    ):
        registry.register(
            PythonAnalyzer(),
        )


def test_registry_replace() -> None:
    registry = SourceAnalyzerRegistry()

    first = PythonAnalyzer()
    second = PythonAnalyzer()

    registry.register(
        first,
    )

    registry.register(
        second,
        replace=True,
    )

    assert (
        registry.require(
            "python-security",
        )
        is second
    )
