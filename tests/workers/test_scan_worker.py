from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import app.models  # noqa: F401
from app.db.base import Base
from app.models.project import Project, ProjectStatus
from app.models.scan_job import ScanJob, ScanStatus
from app.models.user import User, UserStatus
from app.workers.scan_worker import claim_next_scan, recover_stale_scans


def _database(tmp_path: Path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'worker.db'}")
    Base.metadata.create_all(engine)
    return engine


def _project(db: Session) -> Project:
    user = User(
        full_name="Worker Owner",
        email="worker@example.com",
        password_hash="hashed",
        status=UserStatus.ACTIVE,
        is_email_verified=True,
    )
    db.add(user)
    db.flush()
    project = Project(
        user_id=user.id,
        name="Worker Project",
        status=ProjectStatus.SCANNING,
        api_count=0,
        security_score=0,
    )
    db.add(project)
    db.flush()
    return project


def test_claim_next_scan_leases_oldest_queued_job(tmp_path: Path) -> None:
    engine = _database(tmp_path)
    with Session(engine, expire_on_commit=False) as db:
        project = _project(db)
        first = ScanJob(project_id=project.id, status=ScanStatus.QUEUED)
        second = ScanJob(project_id=project.id, status=ScanStatus.QUEUED)
        db.add_all([first, second])
        db.commit()

        claimed_id = claim_next_scan(db, "test-worker")

        assert claimed_id == first.id
        assert first.status == ScanStatus.RUNNING
        assert first.worker_id == "test-worker"
        assert first.attempts == 1
        assert first.heartbeat_at is not None
        assert second.status == ScanStatus.QUEUED


def test_recover_stale_scan_requeues_interrupted_work(tmp_path: Path) -> None:
    engine = _database(tmp_path)
    with Session(engine, expire_on_commit=False) as db:
        project = _project(db)
        scan = ScanJob(
            project_id=project.id,
            status=ScanStatus.RUNNING,
            current_stage="analysis",
            status_message="Analyzing source.",
            heartbeat_at=datetime.now(UTC) - timedelta(hours=1),
            worker_id="stopped-worker",
            attempts=1,
        )
        db.add(scan)
        db.commit()

        recovered = recover_stale_scans(
            db,
            stale_before=datetime.now(UTC) - timedelta(minutes=15),
        )

        assert recovered == 1
        assert scan.status == ScanStatus.QUEUED
        assert scan.current_stage == "queued"
        assert scan.worker_id is None
        assert "Recovered" in scan.status_message
