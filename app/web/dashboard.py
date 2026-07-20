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
