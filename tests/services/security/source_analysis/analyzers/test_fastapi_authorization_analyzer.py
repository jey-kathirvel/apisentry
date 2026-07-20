from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from app.services.security.source_analysis.analyzers.fastapi_authorization import (
    FastAPIAuthorizationSecurityAnalyzer,
)
from app.services.security.source_analysis.context import (
    SourceAnalysisContext,
)
from app.services.security.source_analysis.models import SourceFile


def analyze(content: str):
    raw = content.encode("utf-8")

    source_file = SourceFile(
        path=Path("/tmp/project/app/routes.py"),
        relative_path="app/routes.py",
        language="python",
        content=content,
        size_bytes=len(raw),
        sha256=sha256(raw).hexdigest(),
    )

    return FastAPIAuthorizationSecurityAnalyzer().analyze(
        files=[source_file],
        context=SourceAnalysisContext(
            project_root=Path("/tmp/project"),
            framework="FastAPI",
            language="Python",
        ),
    )


def rule_ids(result) -> set[str]:
    return {
        issue.rule_id
        for issue in result.issues
    }


def test_detects_get_idor() -> None:
    result = analyze(
        '''
@router.get("/users/{user_id}")
async def get_user(user_id: int, db: Session):
    return db.get(User, user_id)
'''
    )

    assert "FASTAPI-AUTH-003" in rule_ids(result)


def test_detects_document_idor() -> None:
    result = analyze(
        '''
@router.get("/documents/{document_id}")
async def get_document(document_id: int, db: Session):
    return db.get(Document, document_id)
'''
    )

    assert "FASTAPI-AUTH-003" in rule_ids(result)


def test_detects_filter_based_idor() -> None:
    result = analyze(
        '''
@router.get("/orders/{order_id}")
async def get_order(order_id: int, db: Session):
    return db.query(Order).filter(Order.id == order_id).first()
'''
    )

    assert "FASTAPI-AUTH-003" in rule_ids(result)


def test_detects_delete_without_ownership() -> None:
    result = analyze(
        '''
@router.delete("/documents/{document_id}")
async def delete_document(document_id: int, db: Session):
    document = db.get(Document, document_id)
    db.delete(document)
    db.commit()
'''
    )

    assert "FASTAPI-AUTH-009" in rule_ids(result)


def test_detects_patch_without_ownership() -> None:
    result = analyze(
        '''
@router.patch("/documents/{document_id}")
async def update_document(document_id: int, payload: DocumentUpdate, db: Session):
    document = db.get(Document, document_id)
    document.title = payload.title
    db.commit()
'''
    )

    assert "FASTAPI-AUTH-009" in rule_ids(result)


def test_detects_put_without_ownership() -> None:
    result = analyze(
        '''
@router.put("/users/{user_id}")
async def update_user(user_id: int, payload: UserUpdate, db: Session):
    user = db.get(User, user_id)
    user.name = payload.name
    db.commit()
'''
    )

    assert "FASTAPI-AUTH-009" in rule_ids(result)


def test_owner_id_check_suppresses_idor() -> None:
    result = analyze(
        '''
@router.get("/documents/{document_id}")
async def get_document(
    document_id: int,
    db: Session,
    current_user = Depends(get_current_user),
):
    document = db.get(Document, document_id)

    if document.owner_id != current_user.id:
        raise HTTPException(status_code=403)

    return document
'''
    )

    assert "FASTAPI-AUTH-003" not in rule_ids(result)


def test_user_id_check_suppresses_missing_ownership() -> None:
    result = analyze(
        '''
@router.delete("/documents/{document_id}")
async def delete_document(
    document_id: int,
    db: Session,
    current_user = Depends(get_current_user),
):
    document = db.get(Document, document_id)

    if document.user_id != current_user.id:
        raise HTTPException(status_code=403)

    db.delete(document)
    db.commit()
'''
    )

    assert "FASTAPI-AUTH-009" not in rule_ids(result)


def test_created_by_check_is_recognized() -> None:
    result = analyze(
        '''
@router.patch("/records/{record_id}")
async def update_record(
    record_id: int,
    db: Session,
    current_user = Depends(get_current_user),
):
    record = db.get(Record, record_id)

    if record.created_by != current_user.id:
        raise HTTPException(status_code=403)

    record.name = "updated"
    db.commit()
'''
    )

    assert "FASTAPI-AUTH-009" not in rule_ids(result)


def test_authorize_helper_suppresses_idor() -> None:
    result = analyze(
        '''
@router.get("/documents/{document_id}")
async def get_document(
    document_id: int,
    db: Session,
    current_user = Depends(get_current_user),
):
    document = db.get(Document, document_id)
    authorize(document, current_user)
    return document
'''
    )

    assert "FASTAPI-AUTH-003" not in rule_ids(result)


def test_require_owner_suppresses_delete_finding() -> None:
    result = analyze(
        '''
@router.delete("/documents/{document_id}")
async def delete_document(
    document_id: int,
    db: Session,
    current_user = Depends(get_current_user),
):
    document = db.get(Document, document_id)
    require_owner(document, current_user)
    db.delete(document)
'''
    )

    assert "FASTAPI-AUTH-009" not in rule_ids(result)


def test_admin_dependency_suppresses_object_findings() -> None:
    result = analyze(
        '''
@router.delete("/admin/users/{user_id}")
async def delete_user(
    user_id: int,
    db: Session,
    current_user = Depends(require_admin),
):
    user = db.get(User, user_id)
    db.delete(user)
'''
    )

    assert "FASTAPI-AUTH-009" not in rule_ids(result)


def test_decorator_permission_dependency_is_recognized() -> None:
    result = analyze(
        '''
@router.delete(
    "/documents/{document_id}",
    dependencies=[Depends(require_permission)],
)
async def delete_document(document_id: int, db: Session):
    document = db.get(Document, document_id)
    db.delete(document)
'''
    )

    assert "FASTAPI-AUTH-009" not in rule_ids(result)


def test_detects_request_role_authorization() -> None:
    result = analyze(
        '''
@router.delete("/system")
async def delete_system(request: DeleteRequest):
    if request.role == "admin":
        return {"deleted": True}

    return {"deleted": False}
'''
    )

    assert "FASTAPI-AUTH-008" in rule_ids(result)


def test_detects_payload_permission_authorization() -> None:
    result = analyze(
        '''
@router.post("/actions")
async def perform_action(payload: ActionRequest):
    if payload.permission == "root":
        return execute_action()
'''
    )

    assert "FASTAPI-AUTH-008" in rule_ids(result)


def test_detects_body_admin_flag_authorization() -> None:
    result = analyze(
        '''
@router.post("/maintenance")
async def maintenance(body: MaintenanceRequest):
    if body.is_admin:
        return run_maintenance()
'''
    )

    assert "FASTAPI-AUTH-008" in rule_ids(result)


def test_current_user_role_is_not_request_controlled() -> None:
    result = analyze(
        '''
@router.get("/admin")
async def admin_panel(
    current_user = Depends(get_current_user),
):
    if current_user.role == "admin":
        return {"allowed": True}
'''
    )

    assert "FASTAPI-AUTH-008" not in rule_ids(result)


def test_endpoint_without_path_identifier_is_not_idor() -> None:
    result = analyze(
        '''
@router.get("/documents")
async def list_documents(db: Session):
    return db.query(Document).all()
'''
    )

    assert "FASTAPI-AUTH-003" not in rule_ids(result)


def test_metadata_and_syntax_error_isolation() -> None:
    successful = analyze(
        '''
@router.get("/health")
async def health():
    return {"status": "ok"}
'''
    )

    broken = analyze("def broken(:\n")

    assert successful.metadata["framework"] == "fastapi"
    assert successful.metadata["endpoints_scanned"] == 1
    assert broken.successful is False
    assert len(broken.errors) == 1
