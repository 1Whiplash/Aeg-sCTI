"""search_history tablosuna geo (cografi konum) sutunu ekle

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-12 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("search_history", sa.Column("geo", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("search_history", "geo")
