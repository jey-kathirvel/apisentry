from __future__ import annotations

import importlib
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.api.dependencies import get_current_user
from app.db.base import Base
from app.db.session import get_db
from app.models.project import Project, ProjectStatus
from app.models.scan_job import ScanJob, ScanStatus
from app.models.user import User, UserStatus


def test_scan_history_and_selected_report_are_owner_scoped(
    tmp_path: Path,
    monkeypatch,
) -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False)
    owner = User(
        full_name="API Owner",
        email="api-owner@example.com",
        password_hash="hashed",
        status=UserStatus.ACTIVE,
        is_email_verified=True,
    )
    db.add(owner)
    db.flush()
    project = Project(
        user_id=owner.id,
        name="Report API",
        status=ProjectStatus.COMPLETED,
        api_count=1,
        security_score=90,
    )
    db.add(project)
    db.flush()
    scan = ScanJob(
        project_id=project.id,
        status=ScanStatus.COMPLETED,
        progress=100,
        current_stage="completed",
        status_message="Completed.",
    )
    db.add(scan)
    db.commit()

    report_file = tmp_path / str(project.id) / str(scan.id) / "security-report.json"
    report_file.parent.mkdir(parents=True)
    report_file.write_text(
        json.dumps({"project": {"id": project.id}, "scan": {"id": scan.id}}),
        encoding="utf-8",
    )

    projects_module = importlib.import_module("app.api.v1.projects")

    def test_report_path(project_id, scan_id, extension, *args, **kwargs):
        return tmp_path / str(project_id) / str(scan_id) / f"security-report.{extension}"

    monkeypatch.setattr(projects_module, "report_path", test_report_path)
    app = FastAPI()
    app.include_router(projects_module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: owner

    with TestClient(app) as client:
        history = client.get(f"/api/v1/projects/{project.id}/scans")
        report = client.get(
            f"/api/v1/projects/{project.id}/report",
            params={"format": "json", "scan_id": scan.id},
        )

    assert history.status_code == 200
    assert history.json()["scans"][0]["report_available"] is True
    assert report.status_code == 200
    assert report.json()["scan"]["id"] == scan.id
    db.close()
