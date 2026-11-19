"""Skema dasar v1.0.0-tesis (idempoten).

Membuat tabel lama bila belum ada dan menambahkan kolom lama scan_history yang mungkin belum dimiliki
basis data versi sangat awal (daftar yang sama dengan init_db() frontend terdahulu).
Dengan demikian, basis data buatan v1 diadopsi tanpa perubahan data.

Revision ID: 0001_baseline_v1
Revises:
Create Date: 2026-11-17
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_baseline_v1"
down_revision = None
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    tables = _tables()

    if "scan_history" not in tables:
        op.create_table(
            "scan_history",
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("batch_id", sa.Text), sa.Column("timestamp", sa.Text),
            sa.Column("scanner_type", sa.Text), sa.Column("key_id", sa.Text),
            sa.Column("cwe_id", sa.Text), sa.Column("component", sa.Text),
            sa.Column("description", sa.Text), sa.Column("predicted_score", sa.Float),
            sa.Column("predicted_severity", sa.Text), sa.Column("execution_duration", sa.Float),
            sa.Column("base_score", sa.Float), sa.Column("shap_base_value", sa.Float),
            sa.Column("shap_total_pos", sa.Float), sa.Column("shap_total_neg", sa.Float),
            sa.Column("absent_vocab_bias", sa.Float), sa.Column("shap_predicted_score", sa.Float),
            sa.Column("shap_positive", sa.Text), sa.Column("shap_negative", sa.Text),
            sa.Column("sast_description", sa.Text), sa.Column("dast_description", sa.Text),
        )
    else:
        legacy_cols = [
            ("batch_id", sa.Text), ("cwe_id", sa.Text), ("execution_duration", sa.Float),
            ("base_score", sa.Float), ("shap_base_value", sa.Float), ("shap_total_pos", sa.Float),
            ("shap_total_neg", sa.Float), ("absent_vocab_bias", sa.Float),
            ("shap_predicted_score", sa.Float), ("shap_positive", sa.Text),
            ("shap_negative", sa.Text), ("sast_description", sa.Text), ("dast_description", sa.Text),
        ]
        existing = _columns("scan_history")
        for name, type_ in legacy_cols:
            if name not in existing:
                op.add_column("scan_history", sa.Column(name, type_))

    if "dataset_metadata" not in tables:
        op.create_table(
            "dataset_metadata",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("total_samples", sa.Integer), sa.Column("train_samples", sa.Integer),
            sa.Column("test_samples", sa.Integer), sa.Column("train_ratio", sa.Float),
            sa.Column("test_ratio", sa.Float), sa.Column("mean_score", sa.Float),
            sa.Column("std_score", sa.Float), sa.Column("min_score", sa.Float),
            sa.Column("max_score", sa.Float), sa.Column("validation_scheme", sa.Text),
            sa.Column("updated_at", sa.Text),
        )

    if "dataset_class_distribution" not in tables:
        op.create_table(
            "dataset_class_distribution",
            sa.Column("severity", sa.Text, primary_key=True),
            sa.Column("count", sa.Integer), sa.Column("proportion", sa.Float),
            sa.Column("score_range", sa.Text),
        )

    if "model_evaluation_metrics" not in tables:
        op.create_table(
            "model_evaluation_metrics",
            sa.Column("algorithm", sa.Text, primary_key=True),
            sa.Column("accuracy", sa.Float), sa.Column("precision", sa.Float),
            sa.Column("recall", sa.Float), sa.Column("f1_score", sa.Float),
            sa.Column("mae", sa.Float), sa.Column("rmse", sa.Float), sa.Column("r2_score", sa.Float),
            sa.Column("training_time_seconds", sa.Float), sa.Column("confusion_matrix_json", sa.Text),
            sa.Column("shap_features_json", sa.Text), sa.Column("updated_at", sa.Text),
        )

    if "sus_responses" not in tables:
        op.create_table(
            "sus_responses",
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("respondent_name", sa.Text), sa.Column("profession", sa.Text),
            *[sa.Column(f"q{i}", sa.Integer) for i in range(1, 11)],
            sa.Column("raw_score", sa.Float), sa.Column("sus_score", sa.Float),
            sa.Column("acceptability", sa.Text), sa.Column("grade_scale", sa.Text),
            sa.Column("created_at", sa.DateTime, server_default=sa.func.current_timestamp()),
        )


def downgrade() -> None:
    # Skema dasar mengadopsi data riset yang sudah ada; data tersebut tidak pernah dihapus secara otomatis.
    pass
