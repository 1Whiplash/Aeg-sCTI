"""search_history ve whitelist tablolarını oluştur

Revision ID: 0001
Revises:
Create Date: 2026-08-10 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ioc_type_enum = postgresql.ENUM("ip", "domain", "url", "hash", name="ioc_type_enum", create_type=False)
severity_enum = postgresql.ENUM("critical", "high", "medium", "low", name="severity_enum", create_type=False)


def upgrade() -> None:
    bind = op.get_bind()
    ioc_type_enum.create(bind, checkfirst=True)
    severity_enum.create(bind, checkfirst=True)

    op.create_table(
        "search_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ioc_value", sa.String(length=512), nullable=False),
        sa.Column("ioc_type", ioc_type_enum, nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column("llm_summary", sa.String(), nullable=True),
        sa.Column("osint_raw", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_search_history_ioc_value", "search_history", ["ioc_value"])

    op.create_table(
        "whitelist",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("ioc_type", ioc_type_enum, nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_whitelist_value", "whitelist", ["value"], unique=True)


def downgrade() -> None:
    op.drop_table("whitelist")
    op.drop_table("search_history")
    severity_enum.drop(op.get_bind(), checkfirst=True)
    ioc_type_enum.drop(op.get_bind(), checkfirst=True)
