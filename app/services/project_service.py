import shutil
from pathlib import Path

from fastapi import UploadFile
from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.project import (
    Project,
    ProjectStatus,
)
from app.models.project_upload import ProjectUpload
from app.models.scan_job import (
    ScanJob,
    ScanStatus,
)
from app.services.archive_service import (
    ArchiveValidationError,
    cleanup_path,
    save_and_extract_upload,
)
from app.services.technology_detector import (
    detect_project_technology,
)


class ProjectServiceError(Exception):
    pass


class ProjectNotFoundError(ProjectServiceError):
    pass


class DuplicateProjectUploadError(ProjectServiceError):
    pass


def enum_value(value) -> str:
    return getattr(value, "value", str(value)).lower()


def get_owned_project(
    db: Session,
    project_id: int,
    user_id: int,
) -> Project:
    project = db.scalar(
        select(Project).where(
            Project.id == project_id,
            Project.user_id == user_id,
        )
    )

    if not project:
        raise ProjectNotFoundError(
            "Project not found."
        )

    return project


def create_project_from_upload(
    db: Session,
    user_id: int,
    name: str,
    description: str | None,
    upload: UploadFile,
) -> Project:
    normalized_name = name.strip()

    if not normalized_name:
        raise ProjectServiceError(
            "Project name is required."
        )

    saved_upload: dict | None = None

    try:
        saved_upload = save_and_extract_upload(
            upload=upload,
            user_id=user_id,
        )

        duplicate = db.scalar(
            select(ProjectUpload).where(
                ProjectUpload.sha256_checksum
                == saved_upload["sha256_checksum"]
            )
        )

        if duplicate:
            cleanup_path(
                Path(saved_upload["archive_path"])
                .parent.parent
            )
            raise DuplicateProjectUploadError(
                "This archive has already been uploaded."
            )

        detection = detect_project_technology(
            saved_upload["project_root"]
        )

        project = Project(
            user_id=user_id,
            name=normalized_name,
            description=(
                description.strip()
                if description
                else None
            ),
            detected_language=(
                detection.primary_language
            ),
            detected_framework=(
                detection.primary_framework
            ),
            version=detection.framework_version,
            status=ProjectStatus.READY,
            api_count=0,
            security_score=0,
        )

        db.add(project)
        db.flush()

        project_upload = ProjectUpload(
            project_id=project.id,
            original_filename=(
                saved_upload["original_filename"]
            ),
            stored_filename=(
                saved_upload["stored_filename"]
            ),
            storage_path=(
                saved_upload["project_root"]
            ),
            sha256_checksum=(
                saved_upload["sha256_checksum"]
            ),
            file_size=saved_upload["file_size"],
        )

        db.add(project_upload)
        db.commit()
        db.refresh(project)

        return project

    except (
        ArchiveValidationError,
        DuplicateProjectUploadError,
        ProjectServiceError,
    ):
        db.rollback()
        raise

    except IntegrityError as exc:
        db.rollback()

        if saved_upload:
            cleanup_path(
                Path(saved_upload["archive_path"])
                .parent.parent
            )

        raise DuplicateProjectUploadError(
            "This archive has already been uploaded."
        ) from exc

    except Exception:
        db.rollback()

        if saved_upload:
            cleanup_path(
                Path(saved_upload["archive_path"])
                .parent.parent
            )

        raise


def list_projects(
    db: Session,
    user_id: int,
) -> list[Project]:
    return list(
        db.scalars(
            select(Project)
            .where(Project.user_id == user_id)
            .order_by(desc(Project.created_at))
        ).all()
    )


def get_project_details(
    db: Session,
    project_id: int,
    user_id: int,
) -> tuple[Project, list[ProjectUpload]]:
    project = get_owned_project(
        db=db,
        project_id=project_id,
        user_id=user_id,
    )

    uploads = list(
        db.scalars(
            select(ProjectUpload)
            .where(
                ProjectUpload.project_id
                == project.id
            )
            .order_by(
                desc(ProjectUpload.uploaded_at)
            )
        ).all()
    )

    return project, uploads


def delete_project(
    db: Session,
    project_id: int,
    user_id: int,
) -> None:
    project, uploads = get_project_details(
        db=db,
        project_id=project_id,
        user_id=user_id,
    )

    upload_roots: set[Path] = set()

    for upload in uploads:
        project_root = Path(
            upload.storage_path
        ).resolve()

        current = project_root

        while (
            current.name not in {"source", "archive"}
            and current.parent != current
        ):
            current = current.parent

        if current.name in {"source", "archive"}:
            upload_roots.add(current.parent)

    db.delete(project)
    db.commit()

    for upload_root in upload_roots:
        cleanup_path(upload_root)


def create_scan_job(
    db: Session,
    project_id: int,
    user_id: int,
) -> ScanJob:
    project = get_owned_project(
        db=db,
        project_id=project_id,
        user_id=user_id,
    )

    active_job = db.scalar(
        select(ScanJob).where(
            ScanJob.project_id == project.id,
            ScanJob.status.in_(
                [
                    ScanStatus.QUEUED,
                    ScanStatus.RUNNING,
                ]
            ),
        )
    )

    if active_job:
        return active_job

    scan_job = ScanJob(
        project_id=project.id,
        status=ScanStatus.QUEUED,
        progress=0,
    )

    project.status = ProjectStatus.SCANNING

    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)

    return scan_job


def get_project_status(
    db: Session,
    project_id: int,
    user_id: int,
) -> tuple[Project, ScanJob | None]:
    project = get_owned_project(
        db=db,
        project_id=project_id,
        user_id=user_id,
    )

    latest_scan = db.scalar(
        select(ScanJob)
        .where(
            ScanJob.project_id == project.id
        )
        .order_by(desc(ScanJob.created_at))
        .limit(1)
    )

    return project, latest_scan
