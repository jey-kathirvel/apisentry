from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
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


class APIResponse(Base):
    __tablename__ = "api_responses"

    __table_args__ = (
        UniqueConstraint(
            "discovered_api_id",
            "status_code",
            name="uq_api_response_status",
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

    status_code: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    response_model: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    content_type: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True,
    )

    schema_json: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    example_json: Mapped[dict | list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )
