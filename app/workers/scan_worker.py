from __future__ import annotations

import os
import signal
import socket
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.project import Project, ProjectStatus
from app.models.scan_job import ScanJob, ScanStatus
from app.services.scan_service import execute_scan


POLL_SECONDS = 2
STALE_AFTER = timedelta(minutes=15)
MAX_ATTEMPTS = 3
_stopping = False


def _utcnow() -> datetime:
    return datetime.now(UTC)


def worker_identity() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def recover_stale_scans(
    db: Session,
    *,
    stale_before: datetime | None = None,
) -> int:
    cutoff = stale_before or (_utcnow() - STALE_AFTER)
    scans = list(
        db.scalars(
            select(ScanJob).where(
                ScanJob.status == ScanStatus.RUNNING,
                or_(
                    ScanJob.heartbeat_at.is_(None),
                    ScanJob.heartbeat_at < cutoff,
                ),
            )
        )
    )

    for scan in scans:
        project = db.get(Project, scan.project_id)
        if scan.attempts >= MAX_ATTEMPTS:
            scan.status = ScanStatus.FAILED
            scan.current_stage = "failed"
            scan.status_message = "Scan recovery limit was reached."
            scan.error_message = "Security scan failed after recovery attempts."
            scan.completed_at = _utcnow()
            scan.estimated_completion_at = None
            if project is not None:
                project.status = ProjectStatus.FAILED
            continue

        scan.status = ScanStatus.QUEUED
        scan.current_stage = "queued"
        scan.status_message = "Recovered after an interrupted worker; queued again."
        scan.worker_id = None
        scan.heartbeat_at = None
        if project is not None:
            project.status = ProjectStatus.SCANNING

    if scans:
        db.commit()
    return len(scans)


def claim_next_scan(db: Session, worker_id: str) -> int | None:
    scan = db.scalar(
        select(ScanJob)
        .where(ScanJob.status == ScanStatus.QUEUED)
        .order_by(ScanJob.created_at, ScanJob.id)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if scan is None:
        db.rollback()
        return None

    now = _utcnow()
    scan.status = ScanStatus.RUNNING
    scan.current_stage = "starting"
    scan.status_message = "A scan worker is starting the analysis."
    scan.worker_id = worker_id
    scan.heartbeat_at = now
    scan.started_at = scan.started_at or now
    scan.attempts += 1
    db.commit()
    return scan.id


def run_once(worker_id: str | None = None) -> bool:
    identity = worker_id or worker_identity()
    with SessionLocal() as db:
        recover_stale_scans(db)
        scan_job_id = claim_next_scan(db, identity)

    if scan_job_id is None:
        return False

    with SessionLocal() as db:
        try:
            execute_scan(db, scan_job_id)
        except Exception:
            return True
    return True


def _stop(*_args) -> None:
    global _stopping
    _stopping = True


def main() -> None:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while not _stopping:
        worked = run_once()
        if not worked:
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
