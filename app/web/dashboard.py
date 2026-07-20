from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates


router = APIRouter(
    tags=["Dashboard"],
)

templates = Jinja2Templates(
    directory="app/templates",
)


@router.get(
    "/dashboard",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def dashboard_page(
    request: Request,
):
    return templates.TemplateResponse(
        request=request,
        name="dashboard/projects.html",
        context={
            "page_title": "API Sentry Dashboard",
        },
    )


@router.get(
    "/scan-monitor",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def scan_monitor_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard/scan_monitor.html",
        context={"page_title": "API Sentry Scan Progress"},
    )


@router.get(
    "/report-viewer",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def report_viewer_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard/report_viewer.html",
        context={"page_title": "API Sentry Security Findings"},
    )


@router.get(
    "/verify-email",
    response_class=HTMLResponse,
    include_in_schema=False,
)
@router.get(
    "/reset-password",
    response_class=HTMLResponse,
    include_in_schema=False,
)
@router.get(
    "/signup",
    response_class=HTMLResponse,
    include_in_schema=False,
)
@router.get(
    "/login",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def authentication_page(
    request: Request,
):
    return templates.TemplateResponse(
        request=request,
        name="dashboard/projects.html",
        context={
            "page_title": "API Sentry Account",
        },
    )
