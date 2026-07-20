from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ProjectUploadResponse(BaseModel):
    id: int
    project_id: int
    original_filename: str
    sha256_checksum: str
    file_size: int
    uploaded_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProjectResponse(BaseModel):
    id: int
    name: str
    description: str | None = None
    detected_language: str | None = None
    detected_framework: str | None = None
    version: str | None = None
    status: str
    api_count: int
    security_score: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProjectDetailResponse(ProjectResponse):
    uploads: list[ProjectUploadResponse] = Field(
        default_factory=list,
    )


class ProjectListResponse(BaseModel):
    projects: list[ProjectResponse]
    total: int


class ScanJobResponse(BaseModel):
    id: int
    project_id: int
    status: str
    progress: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProjectStatusResponse(BaseModel):
    project_id: int
    project_status: str
    latest_scan: ScanJobResponse | None = None
