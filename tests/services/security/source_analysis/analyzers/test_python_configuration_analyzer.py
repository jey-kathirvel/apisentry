from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from app.services.security.source_analysis import (
    PythonConfigurationSecurityAnalyzer,
    SourceAnalysisContext,
    SourceFile,
)


def build_source_file(
    content: str,
    *,
    relative_path: str = "app/config.py",
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
    return (
        PythonConfigurationSecurityAnalyzer()
        .analyze(
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
    )


@pytest.mark.parametrize(
    (
        "content",
        "expected_rule",
    ),
    [
        (
            (
                'API_KEY = '
                '"sk-production-1234567890abcdef"\n'
            ),
            "SECRET-001",
        ),
        (
            (
                'JWT_SECRET = '
                '"this-is-a-hardcoded-signing-secret"\n'
            ),
            "SECRET-001",
        ),
        (
            (
                'SECRET_KEY = "change-me"\n'
            ),
            "SECRET-002",
        ),
        (
            (
                "from fastapi import FastAPI\n"
                "app = FastAPI(debug=True)\n"
            ),
            "CONFIG-001",
        ),
        (
            (
                "import requests\n"
                "requests.get(url, verify=False)\n"
            ),
            "TLS-001",
        ),
        (
            (
                "import jwt\n"
                "jwt.decode(\n"
                "    token,\n"
                "    key,\n"
                '    algorithms=["none"],\n'
                ")\n"
            ),
            "JWT-001",
        ),
        (
            (
                "import jwt\n"
                "jwt.decode(\n"
                "    token,\n"
                "    key,\n"
                "    options={"
                '"verify_signature": False'
                "},\n"
                ")\n"
            ),
            "JWT-002",
        ),
        (
            (
                "app.add_middleware(\n"
                "    CORSMiddleware,\n"
                '    allow_origins=["*"],\n'
                ")\n"
            ),
            "CORS-001",
        ),
        (
            (
                "app.add_middleware(\n"
                "    CORSMiddleware,\n"
                '    allow_origins=["*"],\n'
                "    allow_credentials=True,\n"
                ")\n"
            ),
            "CORS-002",
        ),
    ],
)
def test_detects_configuration_issue(
    content: str,
    expected_rule: str,
) -> None:
    result = analyze(
        content,
    )

    assert result.successful is True

    assert expected_rule in {
        issue.rule_id
        for issue in result.issues
    }


def test_secret_evidence_is_redacted() -> None:
    secret = (
        "sk-production-"
        "1234567890abcdef"
    )

    result = analyze(
        f'API_KEY = "{secret}"\n',
    )

    assert result.issue_count >= 1

    issue = next(
        item
        for item in result.issues
        if item.rule_id == "SECRET-001"
    )

    assert issue.evidence is not None
    assert "[REDACTED]" in issue.evidence
    assert secret not in issue.evidence


def test_environment_secret_is_not_reported() -> None:
    result = analyze(
        (
            "import os\n"
            "API_KEY = os.getenv("
            '"API_KEY"'
            ")\n"
        ),
    )

    assert result.issue_count == 0


def test_safe_debug_configuration() -> None:
    result = analyze(
        (
            "from fastapi import FastAPI\n"
            "app = FastAPI(debug=False)\n"
        ),
    )

    assert result.issue_count == 0


def test_safe_tls_verification() -> None:
    result = analyze(
        (
            "import requests\n"
            "requests.get(\n"
            "    url,\n"
            "    verify=True,\n"
            ")\n"
        ),
    )

    assert result.issue_count == 0


def test_safe_jwt_algorithm() -> None:
    result = analyze(
        (
            "import jwt\n"
            "jwt.decode(\n"
            "    token,\n"
            "    public_key,\n"
            '    algorithms=["RS256"],\n'
            ")\n"
        ),
    )

    assert result.issue_count == 0


def test_safe_cors_allowlist() -> None:
    result = analyze(
        (
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origins=[\n"
            '        "https://app.example.com",\n'
            "    ],\n"
            "    allow_credentials=True,\n"
            ")\n"
        ),
    )

    assert result.issue_count == 0


def test_annotation_assignment_is_scanned() -> None:
    result = analyze(
        (
            "JWT_SECRET: str = "
            '"hardcoded-jwt-secret-123456789"\n'
        ),
    )

    assert "SECRET-001" in {
        issue.rule_id
        for issue in result.issues
    }


def test_attribute_assignment_is_scanned() -> None:
    result = analyze(
        (
            "class Settings:\n"
            "    pass\n"
            "\n"
            "settings = Settings()\n"
            "settings.secret_key = "
            '"hardcoded-session-secret-123456"\n'
        ),
    )

    assert "SECRET-001" in {
        issue.rule_id
        for issue in result.issues
    }


def test_scope_information_is_recorded() -> None:
    result = analyze(
        (
            "class ApiClient:\n"
            "    def request(self, url):\n"
            "        import requests\n"
            "        return requests.get(\n"
            "            url,\n"
            "            verify=False,\n"
            "        )\n"
        ),
    )

    assert result.issue_count == 1

    issue = result.issues[0]

    assert (
        issue.location.class_name
        == "ApiClient"
    )

    assert (
        issue.location.function_name
        == "request"
    )

    assert issue.rule_id == "TLS-001"


def test_multiple_findings_are_preserved() -> None:
    result = analyze(
        (
            'SECRET_KEY = "change-me"\n'
            "\n"
            "import requests\n"
            "requests.get(url, verify=False)\n"
            "\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            '    allow_origins=["*"],\n'
            ")\n"
        ),
    )

    assert {
        issue.rule_id
        for issue in result.issues
    } == {
        "SECRET-002",
        "TLS-001",
        "CORS-001",
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


def test_non_python_file_is_ignored() -> None:
    content = (
        'const API_KEY = "secret";\n'
    )

    content_bytes = content.encode(
        "utf-8",
    )

    source_file = SourceFile(
        path=Path(
            "/tmp/project/config.js",
        ),
        relative_path="config.js",
        language="javascript",
        content=content,
        size_bytes=len(
            content_bytes,
        ),
        sha256=sha256(
            content_bytes,
        ).hexdigest(),
    )

    result = (
        PythonConfigurationSecurityAnalyzer()
        .analyze(
            files=[
                source_file,
            ],
            context=SourceAnalysisContext(
                project_root=Path(
                    "/tmp/project",
                ),
            ),
        )
    )

    assert result.files_scanned == 0
    assert result.issue_count == 0


def test_result_metadata() -> None:
    result = analyze(
        (
            "import requests\n"
            "requests.get(url, verify=False)\n"
        ),
    )

    assert (
        result.metadata["engine"]
        == "python-ast"
    )

    assert (
        "SECRET-001"
        in result.metadata["rule_ids"]
    )

    assert (
        "CORS-002"
        in result.metadata["rule_ids"]
    )
