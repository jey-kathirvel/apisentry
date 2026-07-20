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


class ParameterLocation(str, enum.Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"
    FORM = "form"
    FILE = "file"
    DEPENDENCY = "dependency"
    UNKNOWN = "unknown"


class APIParameter(Base):
    __tablename__ = "api_parameters"

    __table_args__ = (
        UniqueConstraint(
            "discovered_api_id",
            "name",
            "location",
            name="uq_api_parameter_name_location",
        ),
        Index(
            "ix_api_parameters_api_location",
            "discovered_api_id",
            "location",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    discovered_api_id: Mapped[int] = mapped_column(
        ForeignKey(
            "discovered_apis.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    location: Mapped[
        ParameterLocation
    ] = mapped_column(
        Enum(
            ParameterLocation,
            native_enum=False,
            name="parameter_location",
        ),
        default=ParameterLocation.UNKNOWN,
        nullable=False,
    )

    data_type: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    schema_reference: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    required: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    default_value: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    validation_rules: Mapped[
        dict | None
    ] = mapped_column(
        JSON,
        nullable=True,
    )

    example_value: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    sensitive: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    source_line: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )
