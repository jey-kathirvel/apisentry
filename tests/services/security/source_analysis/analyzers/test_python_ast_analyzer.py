from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from app.services.security.source_analysis import (
    PythonASTSecurityAnalyzer,
    SourceAnalysisContext,
    SourceFile,
)


def build_source_file(
    content: str,
    *,
    relative_path: str = "app/main.py",
) -> SourceFile:
    content_bytes = content.encode(
        "utf-8",
    )

    return SourceFile(
        path=Path(
            "/tmp/project",
        )
        / relative_path,
        relative_path=relative_path,
        language="python",
        content=content,
        size_bytes=len(
            content_bytes,
        ),
        sha256=sha256(
            content_bytes,
        ).hexdigest(),
    )


def analyze(
    content: str,
):
    analyzer = PythonASTSecurityAnalyzer()

    return analyzer.analyze(
        files=[
            build_source_file(
                content,
            ),
        ],
        context=SourceAnalysisContext(
            project_root=Path(
                "/tmp/project",
            ),
            framework="FastAPI",
            language="Python",
        ),
    )


@pytest.mark.parametrize(
    (
        "content",
        "expected_rule",
    ),
    [
        (
            "result = eval(user_input)\n",
            "CODE-001",
        ),
        (
            "exec(user_code)\n",
            "CODE-002",
        ),
        (
            "import os\nos.system(command)\n",
            "CMD-002",
        ),
        (
            (
                "import subprocess\n"
                "subprocess.run(command, shell=True)\n"
            ),
            "CMD-001",
        ),
        (
            (
                "import pickle\n"
                "value = pickle.loads(payload)\n"
            ),
            "DESER-001",
        ),
        (
            (
                "import yaml\n"
                "value = yaml.load(payload)\n"
            ),
            "DESER-002",
        ),
        (
            (
                'cursor.execute(f"SELECT * FROM users '
                'WHERE id = {user_id}")\n'
            ),
            "SQL-001",
        ),
        (
            (
                'cursor.execute("SELECT * FROM users '
                'WHERE id = %s" % user_id)\n'
            ),
            "SQL-001",
        ),
        (
            (
                'cursor.execute("SELECT * FROM users '
                'WHERE id = {}".format(user_id))\n'
            ),
            "SQL-001",
        ),
    ],
)
def test_detects_python_security_issue(
    content: str,
    expected_rule: str,
) -> None:
    result = analyze(
        content,
    )

    assert result.successful is True
    assert result.issue_count == 1
    assert (
        result.issues[0].rule_id
        == expected_rule
    )


def test_safe_subprocess_is_not_reported() -> None:
    result = analyze(
        (
            "import subprocess\n"
            "subprocess.run(\n"
            "    ['ls', '-la'],\n"
            "    shell=False,\n"
            "    check=True,\n"
            ")\n"
        ),
    )

    assert result.issue_count == 0


def test_safe_yaml_loader_is_not_reported() -> None:
    result = analyze(
        (
            "import yaml\n"
            "value = yaml.load(\n"
            "    payload,\n"
            "    Loader=yaml.SafeLoader,\n"
            ")\n"
        ),
    )

    assert result.issue_count == 0


def test_yaml_safe_load_is_not_reported() -> None:
    result = analyze(
        (
            "import yaml\n"
            "value = yaml.safe_load(payload)\n"
        ),
    )

    assert result.issue_count == 0


def test_parameterized_sql_is_not_reported() -> None:
    result = analyze(
        (
            "cursor.execute(\n"
            '    "SELECT * FROM users WHERE id = %s",\n'
            "    (user_id,),\n"
            ")\n"
        ),
    )

    assert result.issue_count == 0


def test_records_function_and_class_scope() -> None:
    result = analyze(
        (
            "class CommandService:\n"
            "    def execute_command(self, command):\n"
            "        return eval(command)\n"
        ),
    )

    assert result.issue_count == 1

    issue = result.issues[0]

    assert (
        issue.location.class_name
        == "CommandService"
    )

    assert (
        issue.location.function_name
        == "execute_command"
    )

    assert (
        issue.location.line_start
        == 3
    )

    assert (
        issue.location.column_start
        == 16
    )

    assert issue.evidence == "eval(command)"


def test_detects_multiple_issues() -> None:
    result = analyze(
        (
            "import os\n"
            "import pickle\n"
            "\n"
            "eval(user_input)\n"
            "os.system(command)\n"
            "pickle.loads(payload)\n"
        ),
    )

    assert result.issue_count == 3

    assert {
        issue.rule_id
        for issue in result.issues
    } == {
        "CODE-001",
        "CMD-002",
        "DESER-001",
    }


def test_syntax_error_is_isolated() -> None:
    result = analyze(
        "def broken(:\n",
    )

    assert result.issue_count == 0
    assert result.successful is False
    assert len(
        result.errors,
    ) == 1

    assert (
        "SyntaxError"
        in result.errors[0]
    )

    assert (
        "app/main.py"
        in result.errors[0]
    )


def test_non_python_file_is_ignored() -> None:
    content = "eval(userInput);\n"
    content_bytes = content.encode(
        "utf-8",
    )

    source_file = SourceFile(
        path=Path(
            "/tmp/project/app.js",
        ),
        relative_path="app.js",
        language="javascript",
        content=content,
        size_bytes=len(
            content_bytes,
        ),
        sha256=sha256(
            content_bytes,
        ).hexdigest(),
    )

    result = PythonASTSecurityAnalyzer().analyze(
        files=[
            source_file,
        ],
        context=SourceAnalysisContext(
            project_root=Path(
                "/tmp/project",
            ),
        ),
    )

    assert result.files_scanned == 0
    assert result.issue_count == 0


def test_result_metadata() -> None:
    result = analyze(
        "eval(user_input)\n",
    )

    assert (
        result.metadata["engine"]
        == "python-ast"
    )

    assert (
        "CODE-001"
        in result.metadata["rule_ids"]
    )

    assert (
        "SQL-001"
        in result.metadata["rule_ids"]
    )
