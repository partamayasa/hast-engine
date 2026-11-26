"""Penghapusan tabel kuesioner SUS yang tidak lagi dipakai.

Tabel hanya dihapus bila kosong; bila masih memuat baris, tabel dibiarkan agar tidak ada data yang hilang tanpa cadangan.

Revision ID: 0006_drop_sus_responses
Revises: 0005_recommendation_model_context
Create Date: 2026-11-24
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_drop_sus_responses"
down_revision = "0005_recommendation_model_context"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    if "sus_responses" not in sa.inspect(conn).get_table_names():
        return
    if conn.execute(sa.text("SELECT COUNT(*) FROM sus_responses")).scalar() == 0:
        op.drop_table("sus_responses")


def downgrade() -> None:
    op.create_table(
        "sus_responses",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("respondent_name", sa.Text), sa.Column("profession", sa.Text),
        *[sa.Column(f"q{i}", sa.Integer) for i in range(1, 11)],
        sa.Column("raw_score", sa.Float), sa.Column("sus_score", sa.Float),
        sa.Column("acceptability", sa.Text), sa.Column("grade_scale", sa.Text), sa.Column("ui_version", sa.Text),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.current_timestamp()),
    )
