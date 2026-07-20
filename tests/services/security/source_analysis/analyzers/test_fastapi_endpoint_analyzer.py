from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from app.services.security.source_analysis.analyzers.fastapi_endpoint import (
    FastAPIEndpointSecurityAnalyzer,
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
            "/tmp/project/app/router.py",
        ),
        relative_path="app/router.py",
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
        FastAPIEndpointSecurityAnalyzer()
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


def test_detects_sensitive_endpoint_without_authentication() -> None:
    result = analyze(
        '''
@router.get("/users/{user_id}")
async def get_user(user_id: int):
    return {"id": user_id}
'''
    )

    assert (
        "FASTAPI-AUTH-001"
        in rule_ids(result)
    )


def test_authenticated_endpoint_is_not_reported() -> None:
    result = analyze(
        '''
@router.get("/users/{user_id}")
async def get_user(
    user_id: int,
    current_user = Depends(get_current_user),
):
    return {"id": user_id}
'''
    )

    assert (
        "FASTAPI-AUTH-001"
        not in rule_ids(result)
    )


def test_security_dependency_is_recognized() -> None:
    result = analyze(
        '''
@router.get("/profile")
async def profile(
    user = Security(require_user),
):
    return user
'''
    )

    assert result.issue_count == 0


def test_decorator_dependency_is_recognized() -> None:
    result = analyze(
        '''
@router.get(
    "/admin/report",
    dependencies=[Depends(require_admin)],
)
async def report():
    return {}
'''
    )

    assert result.issue_count == 0


def test_detects_delete_endpoint_without_authorization() -> None:
    result = analyze(
        '''
@router.delete("/documents/{document_id}")
async def delete_document(document_id: int):
    return {"deleted": document_id}
'''
    )

    assert (
        "FASTAPI-AUTH-002"
        in rule_ids(result)
    )


def test_protected_delete_endpoint_is_safe() -> None:
    result = analyze(
        '''
@router.delete("/documents/{document_id}")
async def delete_document(
    document_id: int,
    current_user = Depends(get_current_user),
):
    return {"deleted": document_id}
'''
    )

    assert (
        "FASTAPI-AUTH-002"
        not in rule_ids(result)
    )


def test_detects_unvalidated_upload() -> None:
    result = analyze(
        '''
@router.post("/documents/upload")
async def upload_document(
    file: UploadFile = File(...),
    current_user = Depends(get_current_user),
):
    return {"filename": file.filename}
'''
    )

    assert (
        "FASTAPI-FILE-001"
        in rule_ids(result)
    )


def test_validated_upload_is_not_reported() -> None:
    result = analyze(
        '''
@router.post("/documents/upload")
async def upload_document(
    file: UploadFile = File(...),
    current_user = Depends(get_current_user),
):
    validate_upload(file)
    return {"filename": file.filename}
'''
    )

    assert (
        "FASTAPI-FILE-001"
        not in rule_ids(result)
    )


def test_detects_exception_detail_leak() -> None:
    result = analyze(
        '''
@router.get("/public")
async def public_endpoint():
    try:
        return load_data()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )
'''
    )

    assert (
        "FASTAPI-ERROR-001"
        in rule_ids(result)
    )


def test_detects_exception_return_leak() -> None:
    result = analyze(
        '''
@router.get("/public")
async def public_endpoint():
    try:
        return load_data()
    except Exception as exc:
        return {"error": str(exc)}
'''
    )

    assert (
        "FASTAPI-ERROR-001"
        in rule_ids(result)
    )


def test_safe_exception_response_is_not_reported() -> None:
    result = analyze(
        '''
@router.get("/public")
async def public_endpoint():
    try:
        return load_data()
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Internal server error",
        )
'''
    )

    assert (
        "FASTAPI-ERROR-001"
        not in rule_ids(result)
    )


def test_detects_unvalidated_redirect() -> None:
    result = analyze(
        '''
@router.get("/redirect")
async def redirect(next_url: str):
    return RedirectResponse(next_url)
'''
    )

    assert (
        "FASTAPI-REDIRECT-001"
        in rule_ids(result)
    )


def test_static_redirect_is_not_reported() -> None:
    result = analyze(
        '''
@router.get("/redirect")
async def redirect():
    return RedirectResponse("/dashboard")
'''
    )

    assert (
        "FASTAPI-REDIRECT-001"
        not in rule_ids(result)
    )


def test_public_health_endpoint_is_not_reported() -> None:
    result = analyze(
        '''
@router.get("/health")
async def health():
    return {"status": "ok"}
'''
    )

    assert result.issue_count == 0


def test_endpoint_metadata_is_recorded() -> None:
    result = analyze(
        '''
@router.delete("/users/{user_id}")
async def delete_user(user_id: int):
    return {"deleted": user_id}
'''
    )

    issue = next(
        issue
        for issue in result.issues
        if issue.rule_id
        == "FASTAPI-AUTH-002"
    )

    assert (
        issue.metadata["endpoint_method"]
        == "DELETE"
    )

    assert (
        issue.metadata["endpoint_path"]
        == "/users/{user_id}"
    )

    assert (
        issue.location.function_name
        == "delete_user"
    )


def test_result_metadata_contains_endpoint_count() -> None:
    result = analyze(
        '''
@router.get("/health")
async def health():
    return {"status": "ok"}

@router.get("/users")
async def users():
    return []
'''
    )

    assert (
        result.metadata["framework"]
        == "fastapi"
    )

    assert (
        result.metadata["endpoint_count"]
        == 2
    )


def test_syntax_error_is_isolated() -> None:
    result = analyze(
        "async def broken(:\n",
    )

    assert result.issue_count == 0
    assert result.successful is False
    assert len(
        result.errors,
    ) == 1


def test_non_python_file_is_ignored() -> None:
    content = (
        'app.get("/users", handler);'
    )

    raw = content.encode(
        "utf-8",
    )

    source_file = SourceFile(
        path=Path(
            "/tmp/project/router.js",
        ),
        relative_path="router.js",
        language="javascript",
        content=content,
        size_bytes=len(
            raw,
        ),
        sha256=sha256(
            raw,
        ).hexdigest(),
    )

    result = (
        FastAPIEndpointSecurityAnalyzer()
        .analyze(
            files=[
                source_file,
            ],
            context=SourceAnalysisContext(
                project_root=Path(
                    "/tmp/project",
                ),
                framework="FastAPI",
            ),
        )
    )

    assert result.files_scanned == 0
    assert result.issue_count == 0
