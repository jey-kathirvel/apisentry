from __future__ import annotations

from urllib.parse import urlencode

from app.core.config import settings
from app.services.auth.email_workflow_factory import create_auth_email_workflow


def _url(path: str, **query: object) -> str:
    base = settings.frontend_url.rstrip("/")
    suffix = f"?{urlencode(query)}" if query else ""
    return f"{base}{path}{suffix}"


def notify_project_uploaded(
    *,
    recipient: str,
    full_name: str,
    project_id: int,
    project_name: str,
    framework: str | None,
    language: str | None,
) -> None:
    try:
        create_auth_email_workflow(
            raise_on_delivery_failure=False
        ).send_project_uploaded_email(
            recipient=recipient,
            full_name=full_name,
            project_name=project_name,
            project_url=_url("/dashboard", project_id=project_id),
            framework=framework,
            language=language,
        )
    except Exception:
        return


def notify_scan_completed(
    *,
    recipient: str,
    full_name: str,
    project_id: int,
    project_name: str,
    security_score: int,
    severity_counts: dict[str, int],
) -> None:
    try:
        create_auth_email_workflow(
            raise_on_delivery_failure=False
        ).send_scan_completed_email(
            recipient=recipient,
            full_name=full_name,
            project_name=project_name,
            report_url=_url(
                "/dashboard",
                report_project_id=project_id,
            ),
            security_score=security_score,
            severity_counts=severity_counts,
        )
    except Exception:
        return


def notify_scan_failed(
    *,
    recipient: str,
    full_name: str,
    project_name: str,
) -> None:
    try:
        create_auth_email_workflow(
            raise_on_delivery_failure=False
        ).send_scan_failed_email(
            recipient=recipient,
            full_name=full_name,
            project_name=project_name,
            dashboard_url=_url("/dashboard"),
        )
    except Exception:
        return
