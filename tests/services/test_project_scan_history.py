from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import app.models  # noqa: F401
from app.db.base import Base
from app.models.project import Project, ProjectStatus
from app.models.scan_job import ScanJob, ScanStatus
from app.models.user import User, UserStatus
from app.services.project_service import (
    ProjectNotFoundError,
    get_owned_scan,
    list_project_scans,
)


def test_scan_history_is_ordered_and_owner_scoped(tmp_path: Path) -> None:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'history.db'}"
    )
    Base.metadata.create_all(engine)

    with Session(engine, expire_on_commit=False) as db:
        owner = User(
            full_name="Report Owner",
            email="report-owner@example.com",
            password_hash="hashed",
            status=UserStatus.ACTIVE,
            is_email_verified=True,
        )
        other = User(
            full_name="Other User",
            email="other-report@example.com",
            password_hash="hashed",
            status=UserStatus.ACTIVE,
            is_email_verified=True,
        )
        db.add_all([owner, other])
        db.flush()
        project = Project(
            user_id=owner.id,
            name="History Project",
            status=ProjectStatus.COMPLETED,
            api_count=2,
            security_score=85,
        )
        db.add(project)
        db.flush()
        first = ScanJob(
            project_id=project.id,
            status=ScanStatus.COMPLETED,
            progress=100,
            current_stage="completed",
            status_message="Completed.",
        )
        second = ScanJob(
            project_id=project.id,
            status=ScanStatus.COMPLETED,
            progress=100,
            current_stage="completed",
            status_message="Completed.",
        )
        db.add_all([first, second])
        db.commit()

        selected_project, scans = list_project_scans(
            db,
            project.id,
            owner.id,
        )
        assert selected_project.id == project.id
        assert [scan.id for scan in scans] == [second.id, first.id]

        _, selected_scan = get_owned_scan(
            db,
            project.id,
            first.id,
            owner.id,
        )
        assert selected_scan.id == first.id

        with pytest.raises(ProjectNotFoundError):
            list_project_scans(db, project.id, other.id)
