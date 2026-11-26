"""Keputusan tingkat isu: kolom title dan owner pada dss_decisions.

Revision ID: 0003_issue_decisions
Revises: 0002_dss_structured
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_issue_decisions"
down_revision = "0002_dss_structured"
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("dss_decisions")}
    if "title" not in existing:
        op.add_column("dss_decisions", sa.Column("title", sa.Text))
    if "owner" not in existing:
        op.add_column("dss_decisions", sa.Column("owner", sa.String(128)))


def downgrade() -> None:
    pass
