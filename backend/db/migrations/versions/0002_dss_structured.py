"""Tabel DSS, tabel pengguna, dan kolom terstruktur scan_history.

Revision ID: 0002_dss_structured
Revises: 0001_baseline_v1
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_dss_structured"
down_revision = "0001_baseline_v1"
branch_labels = None
depends_on = None

NEW_SCAN_COLUMNS = [
    ("issue_type", sa.Text), ("has_cwe_tag", sa.Boolean), ("mitigation_text", sa.Text),
    ("sast_score", sa.Float), ("dast_score", sa.Float), ("is_true_positive", sa.Boolean),
    ("sast_key_id", sa.Text), ("dast_key_id", sa.Text), ("sast_component", sa.Text),
    ("dast_component", sa.Text), ("decision_key", sa.Text), ("model_version", sa.Text),
]


def _columns(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    existing = _columns("scan_history")
    for name, type_ in NEW_SCAN_COLUMNS:
        if name not in existing:
            op.add_column("scan_history", sa.Column(name, type_))
    op.create_index("ix_scan_history_decision_key", "scan_history", ["decision_key"], if_not_exists=True)
    op.create_index("ix_scan_history_batch_id", "scan_history", ["batch_id"], if_not_exists=True)

    if "ui_version" not in _columns("sus_responses"):
        op.add_column("sus_responses", sa.Column("ui_version", sa.Text))

    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("full_name", sa.String(128)),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role", sa.String(16), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.current_timestamp()),
        if_not_exists=True,
    )
    op.create_table(
        "dss_runs",
        sa.Column("run_id", sa.String(36), primary_key=True),
        sa.Column("batch_id", sa.Text, nullable=False, index=True),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("weights_json", sa.Text, nullable=False),
        sa.Column("criteria_json", sa.Text, nullable=False),
        sa.Column("weighting_source", sa.String(32)),
        sa.Column("config_hash", sa.String(64)),
        sa.Column("escalation_rate", sa.Float),
        sa.Column("model_version", sa.Text),
        sa.Column("alternatives_count", sa.Integer),
        sa.Column("result_json", sa.Text, nullable=False),
        sa.Column("created_by", sa.String(64)),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.current_timestamp()),
        if_not_exists=True,
    )
    op.create_table(
        "dss_decisions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("decision_key", sa.String(64), nullable=False),
        sa.Column("cwe_id", sa.Text),
        sa.Column("sast_component", sa.Text),
        sa.Column("dast_component", sa.Text),
        sa.Column("last_batch_id", sa.Text),
        sa.Column("last_run_id", sa.String(36)),
        sa.Column("recommended_action", sa.String(32)),
        sa.Column("recommended_rule_id", sa.String(32)),
        sa.Column("chosen_action", sa.String(32)),
        sa.Column("status", sa.String(24), nullable=False, server_default="OPEN"),
        sa.Column("reason", sa.Text),
        sa.Column("asset_criticality", sa.Integer),
        sa.Column("remediation_effort", sa.Integer),
        sa.Column("sla_due_date", sa.String(10)),
        sa.Column("decided_by", sa.String(64)),
        sa.Column("decided_at", sa.DateTime),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.current_timestamp()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.current_timestamp()),
        sa.UniqueConstraint("decision_key", name="uq_dss_decisions_decision_key"),
        if_not_exists=True,
    )
    op.create_table(
        "dss_decision_events",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("decision_id", sa.Integer, sa.ForeignKey("dss_decisions.id", ondelete="CASCADE"), index=True),
        sa.Column("event_type", sa.String(24), nullable=False),
        sa.Column("from_status", sa.String(24)),
        sa.Column("to_status", sa.String(24)),
        sa.Column("chosen_action", sa.String(32)),
        sa.Column("recommended_action", sa.String(32)),
        sa.Column("reason", sa.Text),
        sa.Column("payload_json", sa.Text),
        sa.Column("actor", sa.String(64)),
        sa.Column("run_id", sa.String(36)),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.current_timestamp()),
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_table("dss_decision_events")
    op.drop_table("dss_decisions")
    op.drop_table("dss_runs")
    op.drop_table("users")
    # Kolom tambahan pada scan_history / sus_responses dipertahankan: menghapusnya berarti membuang data.
