# backend/db/models.py
"""
Model ORM SQLAlchemy.

Tabel lama (scan_history, dataset_metadata, dataset_class_distribution,
model_evaluation_metrics) mencerminkan skema v1.0.0-tesis kolom per kolom
sehingga berkas database.db yang sudah ada tetap berfungsi. Kolom dan tabel baru
ditambahkan oleh revisi Alembic 0002 dan seterusnya.
"""
from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Tabel lama (v1.0.0-tesis)
# ---------------------------------------------------------------------------
class ScanHistory(Base):
    """Satu temuan yang sudah diberi skor. Baris dengan scanner_type 'Pengujian Korelasi Hybrid' adalah pasangan SAST-DAST."""
    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    batch_id: Mapped[str | None] = mapped_column(Text)
    timestamp: Mapped[str | None] = mapped_column(Text)
    scanner_type: Mapped[str | None] = mapped_column(Text)
    key_id: Mapped[str | None] = mapped_column(Text)
    cwe_id: Mapped[str | None] = mapped_column(Text)
    component: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    predicted_score: Mapped[float | None] = mapped_column(Float)
    predicted_severity: Mapped[str | None] = mapped_column(Text)
    execution_duration: Mapped[float | None] = mapped_column(Float)
    base_score: Mapped[float | None] = mapped_column(Float)
    shap_base_value: Mapped[float | None] = mapped_column(Float)
    shap_total_pos: Mapped[float | None] = mapped_column(Float)
    shap_total_neg: Mapped[float | None] = mapped_column(Float)
    absent_vocab_bias: Mapped[float | None] = mapped_column(Float)
    shap_predicted_score: Mapped[float | None] = mapped_column(Float)
    shap_positive: Mapped[str | None] = mapped_column(Text)
    shap_negative: Mapped[str | None] = mapped_column(Text)
    sast_description: Mapped[str | None] = mapped_column(Text)
    dast_description: Mapped[str | None] = mapped_column(Text)

    # --- Kolom terstruktur yang ditambahkan pada v2 (revisi 0002) ----------
    issue_type: Mapped[str | None] = mapped_column(Text)
    has_cwe_tag: Mapped[bool | None] = mapped_column(Boolean)
    mitigation_text: Mapped[str | None] = mapped_column(Text)
    sast_score: Mapped[float | None] = mapped_column(Float)
    dast_score: Mapped[float | None] = mapped_column(Float)
    is_true_positive: Mapped[bool | None] = mapped_column(Boolean)
    sast_key_id: Mapped[str | None] = mapped_column(Text)
    dast_key_id: Mapped[str | None] = mapped_column(Text)
    sast_component: Mapped[str | None] = mapped_column(Text)
    dast_component: Mapped[str | None] = mapped_column(Text)
    decision_key: Mapped[str | None] = mapped_column(Text, index=True)
    model_version: Mapped[str | None] = mapped_column(Text)


class DatasetMetadata(Base):
    __tablename__ = "dataset_metadata"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    total_samples: Mapped[int | None] = mapped_column(Integer)
    train_samples: Mapped[int | None] = mapped_column(Integer)
    test_samples: Mapped[int | None] = mapped_column(Integer)
    train_ratio: Mapped[float | None] = mapped_column(Float)
    test_ratio: Mapped[float | None] = mapped_column(Float)
    mean_score: Mapped[float | None] = mapped_column(Float)
    std_score: Mapped[float | None] = mapped_column(Float)
    min_score: Mapped[float | None] = mapped_column(Float)
    max_score: Mapped[float | None] = mapped_column(Float)
    validation_scheme: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[str | None] = mapped_column(Text)


class DatasetClassDistribution(Base):
    __tablename__ = "dataset_class_distribution"

    severity: Mapped[str] = mapped_column(Text, primary_key=True)
    count: Mapped[int | None] = mapped_column(Integer)
    proportion: Mapped[float | None] = mapped_column(Float)
    score_range: Mapped[str | None] = mapped_column(Text)


class ModelEvaluationMetrics(Base):
    __tablename__ = "model_evaluation_metrics"

    algorithm: Mapped[str] = mapped_column(Text, primary_key=True)
    accuracy: Mapped[float | None] = mapped_column(Float)
    precision: Mapped[float | None] = mapped_column(Float)
    recall: Mapped[float | None] = mapped_column(Float)
    f1_score: Mapped[float | None] = mapped_column(Float)
    mae: Mapped[float | None] = mapped_column(Float)
    rmse: Mapped[float | None] = mapped_column(Float)
    r2_score: Mapped[float | None] = mapped_column(Float)
    training_time_seconds: Mapped[float | None] = mapped_column(Float)
    confusion_matrix_json: Mapped[str | None] = mapped_column(Text)
    shap_features_json: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[str | None] = mapped_column(Text)


# ---------------------------------------------------------------------------
# Tabel baru (v2, revisi 0002)
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(128))
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="analyst")  # admin | manager | analyst | developer | auditor
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.current_timestamp())


class DssRun(Base):
    """Satu perhitungan ranking, disimpan bersama seluruh parameter yang diperlukan untuk mereproduksinya."""
    __tablename__ = "dss_runs"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    batch_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    weights_json: Mapped[str] = mapped_column(Text, nullable=False)
    criteria_json: Mapped[str] = mapped_column(Text, nullable=False)
    weighting_source: Mapped[str | None] = mapped_column(String(32))  # config | ahp | manual | entropy
    config_hash: Mapped[str | None] = mapped_column(String(64))
    escalation_rate: Mapped[float | None] = mapped_column(Float)
    model_version: Mapped[str | None] = mapped_column(Text)
    alternatives_count: Mapped[int | None] = mapped_column(Integer)
    result_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.current_timestamp())


class DssDecision(Base):
    """Keputusan analis yang berlaku untuk satu identitas isu (stabil lintas sesi melalui decision_key)."""
    __tablename__ = "dss_decisions"
    __table_args__ = (UniqueConstraint("decision_key", name="uq_dss_decisions_decision_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    decision_key: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str | None] = mapped_column(Text)          # v2.1: judul isu (nama alert ZAP)
    owner: Mapped[str | None] = mapped_column(String(128))   # v2.1: orang/tim penanggung jawab
    cwe_id: Mapped[str | None] = mapped_column(Text)
    sast_component: Mapped[str | None] = mapped_column(Text)
    dast_component: Mapped[str | None] = mapped_column(Text)
    last_batch_id: Mapped[str | None] = mapped_column(Text)
    last_run_id: Mapped[str | None] = mapped_column(String(36))
    recommended_action: Mapped[str | None] = mapped_column(String(32))
    recommended_rule_id: Mapped[str | None] = mapped_column(String(32))
    chosen_action: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="OPEN")
    reason: Mapped[str | None] = mapped_column(Text)
    asset_criticality: Mapped[int | None] = mapped_column(Integer)   # masukan analis 1-5
    remediation_effort: Mapped[int | None] = mapped_column(Integer)  # masukan analis 1-5
    sla_due_date: Mapped[str | None] = mapped_column(String(10))     # tanggal ISO
    decided_by: Mapped[str | None] = mapped_column(String(64))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.current_timestamp())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.current_timestamp(), onupdate=func.current_timestamp()
    )

    events: Mapped[list["DssDecisionEvent"]] = relationship(
        back_populates="decision", cascade="all, delete-orphan", order_by="DssDecisionEvent.id"
    )


class DssDecisionEvent(Base):
    """Jejak audit perubahan keputusan yang hanya dapat ditambah (append-only)."""
    __tablename__ = "dss_decision_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    decision_id: Mapped[int] = mapped_column(ForeignKey("dss_decisions.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(24), nullable=False)  # RECOMMENDED | DECIDED | UPDATED
    from_status: Mapped[str | None] = mapped_column(String(24))
    to_status: Mapped[str | None] = mapped_column(String(24))
    chosen_action: Mapped[str | None] = mapped_column(String(32))
    recommended_action: Mapped[str | None] = mapped_column(String(32))
    reason: Mapped[str | None] = mapped_column(Text)
    payload_json: Mapped[str | None] = mapped_column(Text)
    actor: Mapped[str | None] = mapped_column(String(64))
    run_id: Mapped[str | None] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.current_timestamp())

    decision: Mapped[DssDecision] = relationship(back_populates="events")
