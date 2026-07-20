from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import MessageResponse
from app.schemas.project import (
    ProjectDetailResponse,
    ProjectListResponse,
    ProjectResponse,
    ProjectStatusResponse,
    ProjectUploadResponse,
    ScanJobResponse,
)
from app.services.archive_service import (
    ArchiveValidationError,
)
from app.services.project_service import (
    DuplicateProjectUploadError,
    ProjectNotFoundError,
    ProjectServiceError,
    create_project_from_upload,
    create_scan_job,
    delete_project,
    enum_value,
    get_project_details,
    get_project_status,
    list_projects,
)


router = APIRouter(
    prefix="/projects",
    tags=["Projects"],
)


def serialize_project(project) -> ProjectResponse:
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        detected_language=(
            project.detected_language
        ),
        detected_framework=(
            project.detected_framework
        ),
        version=project.version,
        status=enum_value(project.status),
        api_count=project.api_count,
        security_score=project.security_score,
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


def serialize_upload(upload) -> ProjectUploadResponse:
    return ProjectUploadResponse(
        id=upload.id,
        project_id=upload.project_id,
        original_filename=(
            upload.original_filename
        ),
        sha256_checksum=(
            upload.sha256_checksum
        ),
        file_size=upload.file_size,
        uploaded_at=upload.uploaded_at,
    )


def serialize_scan(scan) -> ScanJobResponse:
    return ScanJobResponse(
        id=scan.id,
        project_id=scan.project_id,
        status=enum_value(scan.status),
        progress=scan.progress,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        created_at=scan.created_at,
    )


@router.post(
    "/upload",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
)
def upload_project(
    name: str = Form(...),
    description: str | None = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):
    try:
        project = create_project_from_upload(
            db=db,
            user_id=current_user.id,
            name=name,
            description=description,
            upload=file,
        )

        return serialize_project(project)

    except ArchiveValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except DuplicateProjectUploadError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    except ProjectServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get(
    "",
    response_model=ProjectListResponse,
)
def get_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):
    projects = list_projects(
        db=db,
        user_id=current_user.id,
    )

    return ProjectListResponse(
        projects=[
            serialize_project(project)
            for project in projects
        ],
        total=len(projects),
    )


@router.get(
    "/{project_id}",
    response_model=ProjectDetailResponse,
)
def get_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):
    try:
        project, uploads = get_project_details(
            db=db,
            project_id=project_id,
            user_id=current_user.id,
        )

        base = serialize_project(project)

        return ProjectDetailResponse(
            **base.model_dump(),
            uploads=[
                serialize_upload(upload)
                for upload in uploads
            ],
        )

    except ProjectNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.delete(
    "/{project_id}",
    response_model=MessageResponse,
)
def remove_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):
    try:
        delete_project(
            db=db,
            project_id=project_id,
            user_id=current_user.id,
        )

        return MessageResponse(
            message="Project deleted successfully."
        )

    except ProjectNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/{project_id}/scan",
    response_model=ScanJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def start_project_scan(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):
    try:
        scan = create_scan_job(
            db=db,
            project_id=project_id,
            user_id=current_user.id,
        )

        return serialize_scan(scan)

    except ProjectNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get(
    "/{project_id}/status",
    response_model=ProjectStatusResponse,
)
def project_status(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):
    try:
        project, latest_scan = (
            get_project_status(
                db=db,
                project_id=project_id,
                user_id=current_user.id,
            )
        )

        return ProjectStatusResponse(
            project_id=project.id,
            project_status=enum_value(
                project.status
            ),
            latest_scan=(
                serialize_scan(latest_scan)
                if latest_scan
                else None
            ),
        )

    except ProjectNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
