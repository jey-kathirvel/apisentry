from datetime import datetime
import enum

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from app.db.base import Base


class HttpMethod(str, enum.Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"
    TRACE = "TRACE"
    CONNECT = "CONNECT"
    ANY = "ANY"


class AuthenticationType(str, enum.Enum):
    PUBLIC = "public"
    JWT = "jwt"
    API_KEY = "api_key"
    BASIC = "basic"
    BEARER = "bearer"
    SESSION = "session"
    OAUTH2 = "oauth2"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class DiscoveryStatus(str, enum.Enum):
    ACTIVE = "active"
    REMOVED = "removed"
    IGNORED = "ignored"


class DiscoveredAPI(Base):
    __tablename__ = "discovered_apis"

    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "http_method",
            "path",
            "source_file",
            "line_number",
            name="uq_discovered_api_location",
        ),
        Index(
            "ix_discovered_apis_project_method",
            "project_id",
            "http_method",
        ),
        Index(
            "ix_discovered_apis_project_path",
            "project_id",
            "path",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    project_id: Mapped[int] = mapped_column(
        ForeignKey(
            "projects.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    scan_job_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "scan_jobs.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    http_method: Mapped[HttpMethod] = mapped_column(
        Enum(
            HttpMethod,
            native_enum=False,
            name="http_method",
        ),
        nullable=False,
    )

    path: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )

    normalized_path: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )

    router_prefix: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    operation_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    function_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    controller_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    framework: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    language: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    source_file: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )

    line_number: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    end_line_number: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    authentication_required: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    authentication_type: Mapped[
        AuthenticationType
    ] = mapped_column(
        Enum(
            AuthenticationType,
            native_enum=False,
            name="authentication_type",
        ),
        default=AuthenticationType.UNKNOWN,
        nullable=False,
    )

    authentication_details: Mapped[
        dict | None
    ] = mapped_column(
        JSON,
        nullable=True,
    )

    tags: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    dependencies: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    request_body_model: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    response_model: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    response_status_code: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    summary: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    deprecated: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    discovery_status: Mapped[
        DiscoveryStatus
    ] = mapped_column(
        Enum(
            DiscoveryStatus,
            native_enum=False,
            name="discovery_status",
        ),
        default=DiscoveryStatus.ACTIVE,
        nullable=False,
    )

    metadata_json: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )
