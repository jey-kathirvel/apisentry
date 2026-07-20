"""add scan cancellation and timeout

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
Create Date: 2026-07-20 16:20:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d2e3f4a5b6c7"
down_revision: Union[str, Sequence[str], None] = "c1d2e3f4a5b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan_jobs",
        sa.Column("deadline_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "scan_jobs",
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_column("scan_jobs", "cancel_requested_at")
    op.drop_column("scan_jobs", "deadline_at")
