from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.api_parameter import APIParameter, ParameterLocation
from app.models.api_response import APIResponse
from app.models.discovered_api import (
    AuthenticationType,
    DiscoveredAPI,
    HttpMethod,
)
from app.models.project import Project, ProjectStatus
from app.models.project_upload import ProjectUpload
from app.models.scan_job import ScanJob, ScanStatus
from app.models.user import User
from app.services.discovery.models import EndpointDiscovery
from app.services.fastapi_ast_discovery import FastAPIASTDiscovery
from app.services.security.analyzer import SecurityAnalyzer
from app.services.security.report_exporter import SecurityReportExporter
from app.services.security.report_generator import SecurityReportGenerator
from app.services.security.models import severity_from_score
from app.services.security.source_analysis import (
    SourceAnalysisContext,
    SourceAnalysisService,
    registry,
)
from app.services.source_code_walker import SourceCodeWalker
from app.services.project_notification_service import (
    notify_scan_completed,
    notify_scan_failed,
)


SOURCE_SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}


class ScanExecutionError(RuntimeError):
    pass


class ScanCancelledError(ScanExecutionError):
    pass


class ScanTimeoutError(ScanExecutionError):
    pass


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _report_directory(
    project_id: int,
    scan_job_id: int,
    report_root: Path | None = None,
) -> Path:
    root = Path(report_root or settings.report_storage_path)
    output = root / str(project_id) / str(scan_job_id)
    output.mkdir(parents=True, exist_ok=True)
    return output


def report_path(
    project_id: int,
    scan_job_id: int,
    extension: str,
    report_root: Path | None = None,
    *,
    create_parent: bool = True,
) -> Path:
    if extension not in {"json", "html"}:
        raise ValueError("Unsupported report format.")

    if create_parent:
        directory = _report_directory(
            project_id,
            scan_job_id,
            report_root,
        )
    else:
        directory = Path(
            report_root or settings.report_storage_path
        ) / str(project_id) / str(scan_job_id)

    return directory / f"security-report.{extension}"


def _source_score(source_result) -> int:
    penalty = sum(
        SOURCE_SEVERITY_WEIGHTS.get(issue.severity.value, 0)
        for issue in source_result.issues
    )
    return max(0, 100 - penalty)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _update_progress(
    db: Session,
    scan: ScanJob,
    *,
    progress: int,
    stage: str,
    message: str,
    check_control: bool = True,
) -> None:
    if check_control:
        _check_scan_control(db, scan)
    now = _utcnow()
    scan.progress = max(0, min(100, progress))
    scan.current_stage = stage
    scan.status_message = message
    scan.heartbeat_at = now

    if scan.started_at is not None and 30 <= scan.progress < 100:
        elapsed = max(
            1,
            (now - _aware(scan.started_at)).total_seconds(),
        )
        remaining = elapsed * (100 - scan.progress) / scan.progress
        scan.estimated_completion_at = now + timedelta(
            seconds=max(5, min(1800, remaining))
        )

    db.commit()


def _check_scan_control(db: Session, scan: ScanJob) -> None:
    db.refresh(scan)
    if scan.cancel_requested_at is not None:
        raise ScanCancelledError("Scan cancellation was requested.")
    if (
        scan.deadline_at is not None
        and _utcnow() >= _aware(scan.deadline_at)
    ):
        raise ScanTimeoutError("Scan deadline was exceeded.")


def _notify_failed_scan(db: Session, project: Project) -> None:
    user = db.get(User, project.user_id)
    if user is not None:
        notify_scan_failed(
            recipient=user.email,
            full_name=user.full_name,
            project_name=project.name,
        )


def _persist_discovery(
    db: Session,
    *,
    project_id: int,
    scan_job_id: int,
    endpoints: list[EndpointDiscovery],
    project_root: Path,
    framework: str | None,
    language: str | None,
) -> None:
    db.execute(
        delete(DiscoveredAPI).where(
            DiscoveredAPI.project_id == project_id,
        )
    )
    db.flush()

    for endpoint in endpoints:
        source_path = Path(endpoint.file_path)
        try:
            source_file = source_path.resolve().relative_to(
                project_root.resolve()
            ).as_posix()
        except ValueError:
            source_file = source_path.name

        method = str(endpoint.method).upper()
        if method not in HttpMethod.__members__:
            method = "ANY"

        record = DiscoveredAPI(
            project_id=project_id,
            scan_job_id=scan_job_id,
            http_method=HttpMethod[method],
            path=endpoint.full_path,
            normalized_path=endpoint.full_path,
            router_prefix=endpoint.router_prefix or None,
            operation_id=endpoint.operation_id,
            function_name=endpoint.function_name,
            framework=framework,
            language=language,
            source_file=source_file,
            line_number=endpoint.line_number,
            authentication_required=endpoint.authentication_required,
            authentication_type=(
                AuthenticationType.UNKNOWN
                if endpoint.authentication_required
                else AuthenticationType.PUBLIC
            ),
            tags=list(endpoint.tags),
            dependencies=list(endpoint.dependencies),
            response_model=endpoint.response_model,
            response_status_code=(
                endpoint.default_status_code or endpoint.status_code
            ),
            summary=endpoint.summary,
            description=endpoint.description,
            deprecated=endpoint.deprecated,
            metadata_json={
                "permission_required": endpoint.permission_required,
                "security_schemes": list(endpoint.security_schemes),
                "security_scopes": list(endpoint.security_scopes),
            },
        )
        db.add(record)
        db.flush()

        for parameter in endpoint.parameters:
            location = str(parameter.location).upper()
            if location not in ParameterLocation.__members__:
                location = "UNKNOWN"

            db.add(
                APIParameter(
                    discovered_api_id=record.id,
                    name=parameter.name,
                    location=ParameterLocation[location],
                    data_type=parameter.python_type,
                    required=parameter.required,
                    default_value=parameter.default_value,
                    description=parameter.description,
                    example_value=parameter.example,
                )
            )

        for response in endpoint.responses:
            db.add(
                APIResponse(
                    discovered_api_id=record.id,
                    status_code=str(response.status_code),
                    description=response.description,
                    response_model=response.model,
                )
            )


def execute_scan(
    db: Session,
    scan_job_id: int,
    *,
    report_root: Path | None = None,
) -> None:
    scan = db.get(ScanJob, scan_job_id)
    if scan is None:
        raise ScanExecutionError("Scan job not found.")

    project = db.get(Project, scan.project_id)
    if project is None:
        raise ScanExecutionError("Project not found.")
    upload = db.scalar(
        select(ProjectUpload)
        .where(ProjectUpload.project_id == project.id)
        .order_by(ProjectUpload.uploaded_at.desc())
        .limit(1)
    )
    if upload is None:
        raise ScanExecutionError("Project upload not found.")

    project_root = Path(upload.storage_path).resolve()
    scan.status = ScanStatus.RUNNING
    scan.started_at = scan.started_at or _utcnow()
    scan.error_message = None
    project.status = ProjectStatus.SCANNING
    db.commit()

    try:
        _update_progress(
            db,
            scan,
            progress=10,
            stage="preparing",
            message="Preparing the uploaded source for analysis.",
        )
        if not project_root.is_dir():
            raise ScanExecutionError("Uploaded project source is unavailable.")

        walk_result = SourceCodeWalker().walk(project_root)
        python_files = [
            source.absolute_path
            for source in walk_result.source_files
            if source.language == "Python"
        ]
        _update_progress(
            db,
            scan,
            progress=30,
            stage="inventory",
            message=(
                f"Indexed {walk_result.total_files} files; "
                "identifying API routes."
            ),
        )

        discovery = FastAPIASTDiscovery()
        endpoints = discovery.discover_directory(python_files)
        _update_progress(
            db,
            scan,
            progress=50,
            stage="discovery",
            message=f"Discovered {len(endpoints)} API endpoints.",
        )

        endpoint_result = SecurityAnalyzer().analyze_endpoints(endpoints)
        endpoint_result.project_id = project.id
        endpoint_result.project_name = project.name
        endpoint_result.framework = project.detected_framework

        source_result = SourceAnalysisService(
            analyzer_registry=registry,
        ).analyze(
            context=SourceAnalysisContext(
                project_root=project_root,
                project_id=project.id,
                project_name=project.name,
                framework=project.detected_framework,
                language=project.detected_language,
            )
        )
        _update_progress(
            db,
            scan,
            progress=70,
            stage="analysis",
            message=(
                f"Analyzed {source_result.files_scanned} source files "
                f"and found {source_result.issue_count} source issues."
            ),
        )

        _persist_discovery(
            db,
            project_id=project.id,
            scan_job_id=scan.id,
            endpoints=endpoints,
            project_root=project_root,
            framework=project.detected_framework,
            language=project.detected_language,
        )
        _update_progress(
            db,
            scan,
            progress=85,
            stage="reporting",
            message="Calculating the score and generating reports.",
        )

        source_score = _source_score(source_result)
        overall_score = round((endpoint_result.score + source_score) / 2)
        report = SecurityReportGenerator.generate(endpoint_result)
        report["project"] = {
            "id": project.id,
            "name": project.name,
            "framework": project.detected_framework,
            "language": project.detected_language,
        }
        report["scan"] = {
            "id": scan.id,
            "endpoint_count": len(endpoints),
            "discovery_errors": discovery.get_errors(),
            "files_scanned": source_result.files_scanned,
        }
        report["source_analysis"] = source_result.to_dict()
        report["summary"]["endpoint_score"] = endpoint_result.score
        report["summary"]["source_score"] = source_score
        report["summary"]["score"] = overall_score
        report["summary"]["severity"] = severity_from_score(
            overall_score
        ).value
        severity_counts = endpoint_result.severity_counts()
        for issue in source_result.issues:
            severity = issue.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        report["summary"]["severity_counts"] = severity_counts

        json_path = report_path(project.id, scan.id, "json", report_root)
        json_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        SecurityReportExporter.export_html(
            endpoint_result,
            report_path(project.id, scan.id, "html", report_root),
        )

        project.api_count = len(endpoints)
        project.security_score = overall_score
        project.status = ProjectStatus.COMPLETED
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = _utcnow()
        scan.estimated_completion_at = scan.completed_at
        _update_progress(
            db,
            scan,
            progress=100,
            stage="completed",
            message="Security scan completed successfully.",
            check_control=False,
        )
        user = db.get(User, project.user_id)
        if user is not None:
            notify_scan_completed(
                recipient=user.email,
                full_name=user.full_name,
                project_id=project.id,
                project_name=project.name,
                security_score=overall_score,
                severity_counts=severity_counts,
            )
    except ScanCancelledError:
        db.rollback()
        cancelled_scan = db.get(ScanJob, scan_job_id)
        if cancelled_scan is not None:
            cancelled_scan.status = ScanStatus.CANCELLED
            cancelled_scan.current_stage = "cancelled"
            cancelled_scan.status_message = "Security scan cancelled."
            cancelled_scan.completed_at = _utcnow()
            cancelled_scan.heartbeat_at = cancelled_scan.completed_at
            cancelled_scan.estimated_completion_at = None
            cancelled_project = db.get(Project, cancelled_scan.project_id)
            if cancelled_project is not None:
                cancelled_project.status = ProjectStatus.READY
            db.commit()
    except ScanTimeoutError:
        db.rollback()
        timed_out_scan = db.get(ScanJob, scan_job_id)
        if timed_out_scan is not None:
            timed_out_scan.status = ScanStatus.FAILED
            timed_out_scan.current_stage = "timed_out"
            timed_out_scan.status_message = "Security scan exceeded its time limit."
            timed_out_scan.completed_at = _utcnow()
            timed_out_scan.heartbeat_at = timed_out_scan.completed_at
            timed_out_scan.estimated_completion_at = None
            timed_out_scan.error_message = "Security scan timed out."
            timed_out_project = db.get(Project, timed_out_scan.project_id)
            if timed_out_project is not None:
                timed_out_project.status = ProjectStatus.FAILED
                db.commit()
                _notify_failed_scan(db, timed_out_project)
            else:
                db.commit()
    except Exception:
        db.rollback()
        failed_scan = db.get(ScanJob, scan_job_id)
        if failed_scan is not None:
            failed_scan.status = ScanStatus.FAILED
            failed_scan.progress = min(failed_scan.progress, 99)
            failed_scan.current_stage = "failed"
            failed_scan.status_message = "The scan stopped before completion."
            failed_scan.completed_at = _utcnow()
            failed_scan.heartbeat_at = failed_scan.completed_at
            failed_scan.estimated_completion_at = None
            failed_scan.error_message = "Security scan failed."
            failed_project = db.get(Project, failed_scan.project_id)
            if failed_project is not None:
                failed_project.status = ProjectStatus.FAILED
            db.commit()
            if failed_project is not None:
                _notify_failed_scan(db, failed_project)
        raise
