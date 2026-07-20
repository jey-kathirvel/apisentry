from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.exceptions import APIError
from app.web.dashboard import router as dashboard_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    Path(settings.project_storage_path).mkdir(
        parents=True,
        exist_ok=True,
    )

    Path(settings.report_storage_path).mkdir(
        parents=True,
        exist_ok=True,
    )

    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    debug=settings.app_debug,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        settings.frontend_url,
        settings.app_url,
    ],
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Requested-With",
    ],
)


app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static",
)


@app.exception_handler(APIError)
async def api_error_handler(
    request: Request,
    exc: APIError,
) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": {
                "code": exc.error_code,
                "message": exc.message,
                "details": exc.details,
            },
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    if settings.app_debug:
        message = str(exc)
    else:
        message = "An unexpected server error occurred."

    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": "internal_server_error",
                "message": message,
            },
        },
    )


@app.get("/")
def application_root() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "status": "running",
        "documentation": "/api/docs",
    }


app.include_router(
    api_router,
    prefix="/api/v1",
)

app.include_router(dashboard_router)
