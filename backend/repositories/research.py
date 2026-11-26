# backend/repositories/research.py
"""Tabel riset: metadata dataset, distribusi kelas, dan evaluasi model."""
import datetime
import json

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.db.models import (
    DatasetClassDistribution, DatasetMetadata, ModelEvaluationMetrics,
)


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# --- Metadata dataset -------------------------------------------------------
def save_dataset_metadata(session: Session, meta: dict, class_dist: list[dict]) -> None:
    row = session.get(DatasetMetadata, 1) or DatasetMetadata(id=1)
    row.total_samples = int(meta.get("total_samples", 0))
    row.train_samples = int(meta.get("train_samples", 0))
    row.test_samples = int(meta.get("test_samples", 0))
    row.train_ratio = float(meta.get("train_ratio", 0.8))
    row.test_ratio = float(meta.get("test_ratio", 0.2))
    row.mean_score = float(meta.get("mean_score", 0.0))
    row.std_score = float(meta.get("std_score", 0.0))
    row.min_score = float(meta.get("min_score", 0.0))
    row.max_score = float(meta.get("max_score", 10.0))
    row.validation_scheme = str(meta.get("validation_scheme", "5-Fold Cross-Validation"))
    row.updated_at = _now()
    session.merge(row)

    session.execute(delete(DatasetClassDistribution))
    for item in class_dist:
        session.merge(DatasetClassDistribution(
            severity=str(item.get("severity", item.get("Severity Level", item.get("Tingkat Keparahan", "")))),
            count=int(item.get("count", item.get("Jumlah Entri", 0))),
            proportion=float(item.get("proportion", item.get("Proporsi", 0.0))),
            score_range=str(item.get("score_range", item.get("Rentang Skor", ""))),
        ))
    session.flush()


def load_dataset_metadata(session: Session) -> dict | None:
    r = session.get(DatasetMetadata, 1)
    if r is None:
        return None
    return {
        "total_samples": r.total_samples, "train_samples": r.train_samples, "test_samples": r.test_samples,
        "train_ratio": r.train_ratio, "test_ratio": r.test_ratio, "mean_score": r.mean_score,
        "std_score": r.std_score, "min_score": r.min_score, "max_score": r.max_score,
        "validation_scheme": r.validation_scheme, "updated_at": r.updated_at,
    }


def load_class_distribution(session: Session) -> list[dict]:
    rows = session.scalars(select(DatasetClassDistribution).order_by(DatasetClassDistribution.count.desc()))
    return [
        {"Severity Level": r.severity, "Jumlah Entri": r.count, "Proporsi": r.proportion,
         "Rentang Skor": r.score_range}
        for r in rows
    ]


# --- Evaluasi model --------------------------------------------------------
def save_model_evaluation(session: Session, ev: dict) -> None:
    shap_dict = ev.get("top_contributing_features", ev.get("shap_features", {}))
    session.merge(ModelEvaluationMetrics(
        algorithm=str(ev.get("algorithm", "Random Forest Regressor")),
        accuracy=float(ev.get("accuracy", 0.0)), precision=float(ev.get("precision", 0.0)),
        recall=float(ev.get("recall", 0.0)), f1_score=float(ev.get("f1_score", 0.0)),
        mae=float(ev.get("mae", 0.0)), rmse=float(ev.get("rmse", 0.0)), r2_score=float(ev.get("r2_score", 0.0)),
        training_time_seconds=float(ev.get("training_time_seconds", 0.0)),
        confusion_matrix_json=json.dumps(ev.get("confusion_matrix", [])),
        shap_features_json=json.dumps(shap_dict), updated_at=_now(),
    ))
    session.flush()


def load_model_evaluation(session: Session, algorithm: str = "Random Forest Regressor") -> dict | None:
    r = session.get(ModelEvaluationMetrics, algorithm)
    if r is None:
        return None
    return {
        "algorithm": r.algorithm, "accuracy": r.accuracy, "precision": r.precision, "recall": r.recall,
        "f1_score": r.f1_score, "mae": r.mae, "rmse": r.rmse, "r2_score": r.r2_score,
        "training_time_seconds": r.training_time_seconds,
        "confusion_matrix": json.loads(r.confusion_matrix_json) if r.confusion_matrix_json else [],
        "top_contributing_features": json.loads(r.shap_features_json) if r.shap_features_json else {},
        "updated_at": r.updated_at,
    }
