from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from app.services.security.source_analysis.analyzers.fastapi_authentication import (
    FastAPIAuthenticationSecurityAnalyzer,
)
from app.services.security.source_analysis.context import (
    SourceAnalysisContext,
)
from app.services.security.source_analysis.models import (
    SourceFile,
)


def analyze(
    content: str,
):
    raw = content.encode(
        "utf-8",
    )

    source_file = SourceFile(
        path=Path(
            "/tmp/project/app/auth.py",
        ),
        relative_path="app/auth.py",
        language="python",
        content=content,
        size_bytes=len(
            raw,
        ),
        sha256=sha256(
            raw,
        ).hexdigest(),
    )

    return (
        FastAPIAuthenticationSecurityAnalyzer()
        .analyze(
            files=[
                source_file,
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


def rule_ids(
    result,
) -> set[str]:
    return {
        issue.rule_id
        for issue in result.issues
    }


def test_detects_jwt_signature_verification_disabled() -> None:
    result = analyze(
        '''
def decode_token(token: str):
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],
        options={"verify_signature": False},
    )
'''
    )

    assert (
        "FASTAPI-AUTH-006"
        in rule_ids(result)
    )


def test_detects_missing_jwt_audience() -> None:
    result = analyze(
        '''
def decode_token(token: str):
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],
    )
'''
    )

    assert (
        "FASTAPI-AUTH-004"
        in rule_ids(result)
    )


def test_detects_missing_jwt_issuer() -> None:
    result = analyze(
        '''
def decode_token(token: str):
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],
    )
'''
    )

    assert (
        "FASTAPI-AUTH-005"
        in rule_ids(result)
    )


def test_secure_jwt_decode_is_not_reported() -> None:
    result = analyze(
        '''
def decode_token(token: str):
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],
        audience="api-sentry",
        issuer="api-sentry-auth",
    )
'''
    )

    assert (
        "FASTAPI-AUTH-004"
        not in rule_ids(result)
    )

    assert (
        "FASTAPI-AUTH-005"
        not in rule_ids(result)
    )

    assert (
        "FASTAPI-AUTH-006"
        not in rule_ids(result)
    )


def test_disabled_audience_validation_is_not_reported_as_missing() -> None:
    result = analyze(
        '''
def decode_token(token: str):
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],
        options={"verify_aud": False},
        issuer="api-sentry-auth",
    )
'''
    )

    assert (
        "FASTAPI-AUTH-004"
        not in rule_ids(result)
    )


def test_disabled_issuer_validation_is_not_reported_as_missing() -> None:
    result = analyze(
        '''
def decode_token(token: str):
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],
        options={"verify_iss": False},
        audience="api-sentry",
    )
'''
    )

    assert (
        "FASTAPI-AUTH-005"
        not in rule_ids(result)
    )


def test_detects_anonymous_admin_endpoint() -> None:
    result = analyze(
        '''
@router.get("/admin/users")
async def list_admin_users():
    return []
'''
    )

    assert (
        "FASTAPI-AUTH-007"
        in rule_ids(result)
    )


def test_protected_admin_endpoint_is_not_reported() -> None:
    result = analyze(
        '''
@router.get("/admin/users")
async def list_admin_users(
    current_user = Depends(require_admin),
):
    return []
'''
    )

    assert (
        "FASTAPI-AUTH-007"
        not in rule_ids(result)
    )


def test_decorator_admin_dependency_is_recognized() -> None:
    result = analyze(
        '''
@router.get(
    "/admin/users",
    dependencies=[Depends(require_admin)],
)
async def list_admin_users():
    return []
'''
    )

    assert (
        "FASTAPI-AUTH-007"
        not in rule_ids(result)
    )


def test_detects_role_assignment_from_payload() -> None:
    result = analyze(
        '''
@router.post("/users")
async def create_user(payload: UserCreate):
    user = User()
    user.role = payload.role
    return user
'''
    )

    assert (
        "FASTAPI-AUTH-010"
        in rule_ids(result)
    )


def test_detects_admin_flag_assignment_from_request() -> None:
    result = analyze(
        '''
@router.patch("/users/{user_id}")
async def update_user(
    user_id: int,
    request: UserUpdate,
):
    user.is_admin = request.is_admin
    return user
'''
    )

    assert (
        "FASTAPI-AUTH-010"
        in rule_ids(result)
    )


def test_detects_permission_assignment_from_dictionary() -> None:
    result = analyze(
        '''
def update_permissions(data):
    user.permissions = data["permissions"]
'''
    )

    assert (
        "FASTAPI-AUTH-010"
        in rule_ids(result)
    )


def test_safe_static_role_assignment_is_not_reported() -> None:
    result = analyze(
        '''
def create_user():
    user = User()
    user.role = "member"
    return user
'''
    )

    assert (
        "FASTAPI-AUTH-010"
        not in rule_ids(result)
    )


def test_normal_profile_endpoint_is_not_admin_endpoint() -> None:
    result = analyze(
        '''
@router.get("/profile")
async def profile():
    return {}
'''
    )

    assert (
        "FASTAPI-AUTH-007"
        not in rule_ids(result)
    )


def test_endpoint_metadata_is_recorded() -> None:
    result = analyze(
        '''
@router.delete("/admin/users/{user_id}")
async def delete_admin_user(user_id: int):
    return {"deleted": user_id}
'''
    )

    issue = next(
        issue
        for issue in result.issues
        if issue.rule_id
        == "FASTAPI-AUTH-007"
    )

    assert (
        issue.metadata["endpoint_method"]
        == "DELETE"
    )

    assert (
        issue.metadata["endpoint_path"]
        == "/admin/users/{user_id}"
    )


def test_analyzer_metadata_is_recorded() -> None:
    result = analyze(
        '''
@router.get("/health")
async def health():
    return {"status": "ok"}
'''
    )

    assert (
        result.metadata["framework"]
        == "fastapi"
    )

    assert (
        result.metadata["endpoints_scanned"]
        == 1
    )


def test_syntax_error_is_isolated() -> None:
    result = analyze(
        "def broken(:\n",
    )

    assert result.issue_count == 0
    assert result.successful is False
    assert len(
        result.errors,
    ) == 1
