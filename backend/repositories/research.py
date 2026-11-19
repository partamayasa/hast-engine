# backend/repositories/research.py
"""Tabel riset: metadata dataset, distribusi kelas, evaluasi model, dan respons SUS."""
import datetime
import json

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.db.models import (
    DatasetClassDistribution, DatasetMetadata, ModelEvaluationMetrics, SusResponse,
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


# --- SUS ----------------------------------------------------------------------
def calculate_sus_score(answers: dict) -> tuple[float, float, str, str]:
    """
    Penskoran SUS (Brooke): butir ganjil skor-1, butir genap 5-skor, jumlah x 2,5 (0-100).
    Ambang tidak berubah dari v1.0.0-tesis.
    """
    raw_score = 0.0
    for i in range(1, 11):
        try:
            val = int(answers.get(f"q{i}", 3))
        except (ValueError, TypeError):
            val = 3
        raw_score += (val - 1) if i % 2 == 1 else (5 - val)
    sus_score = round(raw_score * 2.5, 2)

    if sus_score >= 70.0:
        acceptability = "Acceptable"
    elif sus_score >= 50.0:
        acceptability = "Marginal"
    else:
        acceptability = "Not Acceptable"

    if sus_score >= 84.1:
        grade = "Best Imaginable (A)"
    elif sus_score >= 80.3:
        grade = "Excellent (A-)"
    elif sus_score >= 68.0:
        grade = "Good (B/C)"
    elif sus_score >= 51.0:
        grade = "OK / Fair (D)"
    else:
        grade = "Poor (F)"
    return raw_score, sus_score, acceptability, grade


def save_sus_response(session: Session, respondent_name: str, profession: str, answers: dict,
                      ui_version: str | None = None) -> int:
    raw_score, sus_score, acceptability, grade = calculate_sus_score(answers)
    row = SusResponse(
        respondent_name=str(respondent_name).strip(), profession=str(profession).strip(),
        **{f"q{i}": int(answers.get(f"q{i}", 3)) for i in range(1, 11)},
        raw_score=raw_score, sus_score=sus_score, acceptability=acceptability, grade_scale=grade,
        ui_version=ui_version,
    )
    session.add(row)
    session.flush()
    return row.id


def load_all_sus_responses(session: Session) -> list[dict]:
    out = []
    for r in session.scalars(select(SusResponse).order_by(SusResponse.id)):
        out.append({
            "ID": f"R{r.id:02d}", "Nama / Inisial": r.respondent_name, "Profesi / Role": r.profession,
            **{f"Q{i}": getattr(r, f"q{i}") for i in range(1, 11)},
            "Skor Mentah": r.raw_score, "Skor SUS": r.sus_score, "Tingkat Penerimaan": r.acceptability,
            "Kategori Kualitatif": r.grade_scale,
            "Versi UI": r.ui_version or "v1",
            "Waktu Pengisian": str(r.created_at)[:16] if r.created_at else "N/A",
        })
    return out
