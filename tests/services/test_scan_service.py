from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

import app.models  # noqa: F401
from app.db.base import Base
from app.models.discovered_api import DiscoveredAPI
from app.models.project import Project, ProjectStatus
from app.models.project_upload import ProjectUpload
from app.models.scan_job import ScanJob, ScanStatus
from app.models.user import User, UserStatus
from app.services.scan_service import execute_scan, report_path


def test_execute_scan_discovers_analyzes_and_persists_report(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "main.py").write_text(
        """
from fastapi import FastAPI

app = FastAPI()

@app.get('/public')
def public_endpoint():
    return {'ok': True}

@app.post('/users/{user_id}', status_code=201)
def update_user(user_id: int):
    return {'id': user_id}
""".strip(),
        encoding="utf-8",
    )

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'scan.db'}"
    )
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        user = User(
            full_name="Scan Owner",
            email="owner@example.com",
            password_hash="hashed",
            status=UserStatus.ACTIVE,
            is_email_verified=True,
        )
        db.add(user)
        db.flush()

        project = Project(
            user_id=user.id,
            name="Example API",
            detected_language="Python",
            detected_framework="FastAPI",
            status=ProjectStatus.SCANNING,
            api_count=0,
            security_score=0,
        )
        db.add(project)
        db.flush()
        db.add(
            ProjectUpload(
                project_id=project.id,
                original_filename="example.zip",
                stored_filename="example.zip",
                storage_path=str(source_root),
                sha256_checksum="a" * 64,
                file_size=100,
            )
        )
        scan = ScanJob(
            project_id=project.id,
            status=ScanStatus.QUEUED,
            progress=0,
        )
        db.add(scan)
        db.commit()

        execute_scan(
            db,
            scan.id,
            report_root=tmp_path / "reports",
        )

        db.refresh(scan)
        db.refresh(project)
        discovered = list(
            db.scalars(
                select(DiscoveredAPI).where(
                    DiscoveredAPI.project_id == project.id
                )
            )
        )

        assert scan.status == ScanStatus.COMPLETED
        assert scan.progress == 100
        assert scan.started_at is not None
        assert scan.completed_at is not None
        assert project.status == ProjectStatus.COMPLETED
        assert project.api_count == 2
        assert 0 <= project.security_score <= 100
        assert {endpoint.path for endpoint in discovered} == {
            "/public",
            "/users/{user_id}",
        }

        json_report = report_path(
            project.id,
            scan.id,
            "json",
            tmp_path / "reports",
        )
        html_report = report_path(
            project.id,
            scan.id,
            "html",
            tmp_path / "reports",
        )
        payload = json.loads(json_report.read_text(encoding="utf-8"))

        assert json_report.is_file()
        assert html_report.is_file()
        assert payload["project"]["id"] == project.id
        assert payload["scan"]["endpoint_count"] == 2
        assert "source_analysis" in payload


def test_execute_scan_marks_missing_source_as_failed(tmp_path: Path) -> None:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'failed.db'}"
    )
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        user = User(
            full_name="Scan Owner",
            email="failed@example.com",
            password_hash="hashed",
            status=UserStatus.ACTIVE,
            is_email_verified=True,
        )
        db.add(user)
        db.flush()
        project = Project(
            user_id=user.id,
            name="Missing Source",
            status=ProjectStatus.SCANNING,
            api_count=0,
            security_score=0,
        )
        db.add(project)
        db.flush()
        db.add(
            ProjectUpload(
                project_id=project.id,
                original_filename="missing.zip",
                stored_filename="missing.zip",
                storage_path=str(tmp_path / "missing"),
                sha256_checksum="b" * 64,
                file_size=100,
            )
        )
        scan = ScanJob(
            project_id=project.id,
            status=ScanStatus.QUEUED,
            progress=0,
        )
        db.add(scan)
        db.commit()

        try:
            execute_scan(db, scan.id, report_root=tmp_path / "reports")
        except Exception:
            pass

        db.refresh(scan)
        db.refresh(project)
        assert scan.status == ScanStatus.FAILED
        assert project.status == ProjectStatus.FAILED
        assert scan.error_message == "Security scan failed."
