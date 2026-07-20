from __future__ import annotations

from pathlib import Path

from app.services.security.source_analysis import (
    SourceAnalysisContext,
    SourceAnalysisResult,
    SourceAnalysisService,
    SourceAnalyzer,
    SourceAnalyzerRegistry,
    SourceFile,
    SourceIssue,
    SourceIssueConfidence,
    SourceIssueSeverity,
    SourceLocation,
)


class PythonIssueAnalyzer(
    SourceAnalyzer,
):
    name = "python-issue-analyzer"
    languages = (
        "python",
    )
    priority = 20

    def analyze(
        self,
        *,
        files: list[SourceFile],
        context: SourceAnalysisContext,
    ) -> SourceAnalysisResult:
        issues: list[SourceIssue] = []

        for source_file in files:
            if "eval(" not in source_file.content:
                continue

            issues.append(
                SourceIssue(
                    rule_id="INJ-001",
                    title="Unsafe eval usage",
                    description=(
                        "Dynamic code execution "
                        "was detected."
                    ),
                    category="injection",
                    severity=(
                        SourceIssueSeverity.CRITICAL
                    ),
                    confidence=(
                        SourceIssueConfidence.HIGH
                    ),
                    remediation=(
                        "Remove eval and use a "
                        "safe parser."
                    ),
                    location=SourceLocation(
                        file_path=(
                            source_file.relative_path
                        ),
                        line_start=1,
                    ),
                    evidence="eval(user_input)",
                    cwe_id="CWE-95",
                ),
            )

        return SourceAnalysisResult(
            analyzer=self.name,
            files_scanned=len(
                files,
            ),
            issues=issues,
            metadata={
                "language": "python",
            },
        )


class JavaScriptIssueAnalyzer(
    SourceAnalyzer,
):
    name = "javascript-issue-analyzer"
    languages = (
        "javascript",
    )
    priority = 10

    def analyze(
        self,
        *,
        files: list[SourceFile],
        context: SourceAnalysisContext,
    ) -> SourceAnalysisResult:
        issues: list[SourceIssue] = []

        for source_file in files:
            if "innerHTML" not in source_file.content:
                continue

            issues.append(
                SourceIssue(
                    rule_id="XSS-001",
                    title="Unsafe innerHTML assignment",
                    description=(
                        "Untrusted HTML may be "
                        "rendered."
                    ),
                    category="xss",
                    severity=(
                        SourceIssueSeverity.HIGH
                    ),
                    confidence=(
                        SourceIssueConfidence.MEDIUM
                    ),
                    remediation=(
                        "Use safe DOM APIs or "
                        "sanitize input."
                    ),
                    location=SourceLocation(
                        file_path=(
                            source_file.relative_path
                        ),
                        line_start=1,
                    ),
                    evidence=(
                        "element.innerHTML = input"
                    ),
                    cwe_id="CWE-79",
                ),
            )

        return SourceAnalysisResult(
            analyzer=self.name,
            files_scanned=len(
                files,
            ),
            issues=issues,
        )


class DuplicateIssueAnalyzer(
    SourceAnalyzer,
):
    name = "duplicate-issue-analyzer"
    languages = (
        "python",
    )
    priority = 5

    def analyze(
        self,
        *,
        files: list[SourceFile],
        context: SourceAnalysisContext,
    ) -> SourceAnalysisResult:
        issue = SourceIssue(
            rule_id="INJ-001",
            title="Unsafe eval usage",
            description=(
                "Dynamic code execution "
                "was detected."
            ),
            category="injection",
            severity=(
                SourceIssueSeverity.CRITICAL
            ),
            confidence=(
                SourceIssueConfidence.HIGH
            ),
            remediation=(
                "Remove eval and use a safe parser."
            ),
            location=SourceLocation(
                file_path="app/main.py",
                line_start=1,
            ),
            evidence="eval(user_input)",
            cwe_id="CWE-95",
        )

        return SourceAnalysisResult(
            analyzer=self.name,
            files_scanned=len(
                files,
            ),
            issues=[
                issue,
                issue,
            ],
        )


class BrokenAnalyzer(
    SourceAnalyzer,
):
    name = "broken-analyzer"
    languages = (
        "python",
    )
    priority = 30

    def analyze(
        self,
        *,
        files: list[SourceFile],
        context: SourceAnalysisContext,
    ) -> SourceAnalysisResult:
        raise RuntimeError(
            "simulated analyzer failure",
        )


def write_file(
    path: Path,
    content: str,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        content,
        encoding="utf-8",
    )


def test_service_runs_matching_analyzers(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path / "app/main.py",
        "eval(user_input)\n",
    )

    write_file(
        tmp_path / "web/app.js",
        "element.innerHTML = input;\n",
    )

    registry = SourceAnalyzerRegistry(
        [
            PythonIssueAnalyzer(),
            JavaScriptIssueAnalyzer(),
        ],
    )

    service = SourceAnalysisService(
        analyzer_registry=registry,
    )

    result = service.analyze(
        context=SourceAnalysisContext(
            project_root=tmp_path,
            project_id=1,
            project_name="Demo",
        ),
    )

    assert result.files_scanned == 2
    assert result.issue_count == 2
    assert result.successful is True

    assert {
        issue.rule_id
        for issue in result.issues
    } == {
        "INJ-001",
        "XSS-001",
    }

    assert (
        result.metadata["analyzer_count"]
        == 2
    )

    assert (
        result.metadata["summary"]["severity"]
        == {
            "critical": 1,
            "high": 1,
        }
    )

    assert (
        result.metadata["summary"]["categories"]
        == {
            "injection": 1,
            "xss": 1,
        }
    )


def test_service_filters_files_per_analyzer(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path / "app/main.py",
        "print('safe')\n",
    )

    write_file(
        tmp_path / "web/app.js",
        "console.log('safe');\n",
    )

    registry = SourceAnalyzerRegistry(
        [
            PythonIssueAnalyzer(),
            JavaScriptIssueAnalyzer(),
        ],
    )

    result = SourceAnalysisService(
        analyzer_registry=registry,
    ).analyze(
        context=SourceAnalysisContext(
            project_root=tmp_path,
        ),
    )

    analyzer_results = {
        item["analyzer"]: item
        for item in result.metadata[
            "analyzers"
        ]
    }

    assert (
        analyzer_results[
            "python-issue-analyzer"
        ]["files_scanned"]
        == 1
    )

    assert (
        analyzer_results[
            "javascript-issue-analyzer"
        ]["files_scanned"]
        == 1
    )


def test_service_deduplicates_across_analyzers(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path / "app/main.py",
        "eval(user_input)\n",
    )

    registry = SourceAnalyzerRegistry(
        [
            PythonIssueAnalyzer(),
            DuplicateIssueAnalyzer(),
        ],
    )

    result = SourceAnalysisService(
        analyzer_registry=registry,
    ).analyze(
        context=SourceAnalysisContext(
            project_root=tmp_path,
            language="python",
        ),
    )

    assert result.issue_count == 1

    assert (
        result.issues[0].fingerprint
        == "INJ-001|app/main.py|1||"
    )


def test_service_isolates_analyzer_failures(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path / "app/main.py",
        "eval(user_input)\n",
    )

    registry = SourceAnalyzerRegistry(
        [
            BrokenAnalyzer(),
            PythonIssueAnalyzer(),
        ],
    )

    result = SourceAnalysisService(
        analyzer_registry=registry,
    ).analyze(
        context=SourceAnalysisContext(
            project_root=tmp_path,
            language="python",
        ),
    )

    assert result.issue_count == 1
    assert result.successful is False
    assert len(
        result.errors,
    ) == 1

    assert (
        "broken-analyzer"
        in result.errors[0]
    )

    assert (
        "simulated analyzer failure"
        in result.errors[0]
    )

    assert (
        result.metadata["summary"]["error_count"]
        == 1
    )


def test_service_handles_empty_registry(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path / "app/main.py",
        "print('safe')\n",
    )

    result = SourceAnalysisService(
        analyzer_registry=(
            SourceAnalyzerRegistry()
        ),
    ).analyze(
        context=SourceAnalysisContext(
            project_root=tmp_path,
        ),
    )

    assert result.files_scanned == 1
    assert result.issue_count == 0
    assert result.successful is True

    assert (
        result.metadata["analyzer_count"]
        == 0
    )

    assert (
        result.metadata["summary"]["issue_count"]
        == 0
    )


def test_service_reports_skipped_files(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path / "app/main.py",
        "print('safe')\n",
    )

    write_file(
        tmp_path / "venv/lib/test.py",
        "print('excluded')\n",
    )

    result = SourceAnalysisService(
        analyzer_registry=(
            SourceAnalyzerRegistry()
        ),
    ).analyze(
        context=SourceAnalysisContext(
            project_root=tmp_path,
        ),
    )

    assert result.skipped_files == [
        "venv/lib/test.py",
    ]

    assert (
        result.metadata["summary"][
            "skipped_file_count"
        ]
        == 1
    )


def test_service_serialization(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path / "app/main.py",
        "eval(user_input)\n",
    )

    result = SourceAnalysisService(
        analyzer_registry=(
            SourceAnalyzerRegistry(
                [
                    PythonIssueAnalyzer(),
                ],
            )
        ),
    ).analyze(
        context=SourceAnalysisContext(
            project_root=tmp_path,
            framework="FastAPI",
            language="Python",
        ),
    )

    payload = result.to_dict()

    assert (
        payload["analyzer"]
        == "source-analysis-service"
    )

    assert payload["issue_count"] == 1
    assert payload["successful"] is True

    assert (
        payload["metadata"]["framework"]
        == "FastAPI"
    )

    assert (
        payload["metadata"]["language"]
        == "Python"
    )

    assert (
        payload["issues"][0]["rule_id"]
        == "INJ-001"
    )
