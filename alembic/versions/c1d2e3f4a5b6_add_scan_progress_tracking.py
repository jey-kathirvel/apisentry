"""add scan progress tracking

Revision ID: c1d2e3f4a5b6
Revises: aa789c9d234d
Create Date: 2026-07-20 15:30:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c1d2e3f4a5b6"
down_revision: Union[str, Sequence[str], None] = "aa789c9d234d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_jobs",
        sa.Column(
            "current_stage",
            sa.String(length=50),
            nullable=False,
            server_default="queued",
        ),
    )
    op.add_column(
        "scan_jobs",
        sa.Column(
            "status_message",
            sa.String(length=500),
            nullable=False,
            server_default="Waiting for a scan worker.",
        ),
    )
    op.execute(
        "UPDATE scan_jobs SET current_stage = 'completed', "
        "status_message = 'Security scan completed successfully.' "
        "WHERE status = 'COMPLETED'"
    )
    op.execute(
        "UPDATE scan_jobs SET current_stage = 'failed', "
        "status_message = 'The scan stopped before completion.' "
        "WHERE status = 'FAILED'"
    )
    op.execute(
        "UPDATE scan_jobs SET status = 'QUEUED', current_stage = 'queued', "
        "status_message = 'Recovered during the scan worker upgrade.' "
        "WHERE status = 'RUNNING'"
    )
    op.add_column(
        "scan_jobs",
        sa.Column("estimated_completion_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "scan_jobs",
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "scan_jobs",
        sa.Column("worker_id", sa.String(length=150)),
    )
    op.add_column(
        "scan_jobs",
        sa.Column(
            "attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_column("scan_jobs", "attempts")
    op.drop_column("scan_jobs", "worker_id")
    op.drop_column("scan_jobs", "heartbeat_at")
    op.drop_column("scan_jobs", "estimated_completion_at")
    op.drop_column("scan_jobs", "status_message")
    op.drop_column("scan_jobs", "current_stage")
