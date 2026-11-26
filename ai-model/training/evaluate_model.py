# ai-model/training/evaluate_model.py
"""
Evaluasi ulang model Random Forest dengan validasi silang 5-fold TANPA melatih ulang atau menimpa artefak.

Prosedur mengikuti train_production_model.py (skema k-fold): KFold(5, shuffle=True, random_state=42),
hiperparameter dari ai_config.json, dan matriks TF-IDF yang dibentuk dari seluruh data. Matriks TF-IDF
diambil dari vectorizer production yang tersimpan (artifacts/tfidf_vectorizer.pkl), karena vectorizer itulah
yang dibentuk dari seluruh data pada run pelatihan production.

Perbedaan dengan skrip pelatihan: pemetaan skor ke kelas memakai skor yang dibulatkan dua desimal
(keputusan K10). Metrik dengan pemetaan lama juga dihitung sebagai pemeriksaan bahwa replikasi ini
mereproduksi angka production.

Pemakaian:
    uv run python ai-model/training/evaluate_model.py            # hanya menulis JSON hasil
    uv run python ai-model/training/evaluate_model.py --sync-db  # juga memperbarui metrik di basis data
"""
import argparse
import json
import os
import pickle
import sys
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, mean_absolute_error,
                             mean_squared_error, precision_score, r2_score, recall_score)
from sklearn.model_selection import KFold

AI_MODEL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(AI_MODEL_ROOT)
DATA_PATH = os.path.join(AI_MODEL_ROOT, "data", "cve_cvss4_dataset.csv")
TFIDF_PATH = os.path.join(AI_MODEL_ROOT, "artifacts", "tfidf_vectorizer.pkl")
CONFIG_PATH = os.path.join(AI_MODEL_ROOT, "config", "ai_config.json")
OUTPUT_PATH = os.path.join(AI_MODEL_ROOT, "data", "model_reevaluation_result.json")
LABELS = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_rounded(score) -> str:
    """Memetakan skor ke kelas setelah dibulatkan dua desimal (sama dengan backend.config.calculate_severity)."""
    s = round(float(score), 2)
    if s <= 0.0:
        return "NONE"
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s >= 0.1:
        return "LOW"
    return "NONE"


def severity_legacy(score) -> str:
    """Pemetaan lama skrip pelatihan (skor di celah antarkelas jatuh ke CRITICAL); hanya untuk pemeriksaan."""
    if score == 0:
        return "NONE"
    if 0.1 <= score <= 3.9:
        return "LOW"
    if 4.0 <= score <= 6.9:
        return "MEDIUM"
    if 7.0 <= score <= 8.9:
        return "HIGH"
    return "CRITICAL"


def classification_metrics(y_true, y_pred, mapper) -> dict:
    t = [mapper(v) for v in y_true]
    p = [mapper(v) for v in y_pred]
    return {
        "accuracy": accuracy_score(t, p),
        "precision": precision_score(t, p, average="macro", zero_division=0),
        "recall": recall_score(t, p, average="macro", zero_division=0),
        "f1_score": f1_score(t, p, average="macro", zero_division=0),
    }, t, p


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluasi ulang 5-fold tanpa menimpa artefak model.")
    parser.add_argument("--sync-db", action="store_true", help="Perbarui tabel model_evaluation_metrics.")
    args = parser.parse_args()

    with open(CONFIG_PATH, encoding="utf-8") as f:
        rf_params = json.load(f).get("model_hyperparameters", {}).get("random_forest", {})
    df = pd.read_csv(DATA_PATH).dropna(subset=["summary", "cvss_score"]).reset_index(drop=True)
    with open(TFIDF_PATH, "rb") as f:
        tfidf = pickle.load(f)
    X = tfidf.transform(df["summary"])
    y = df["cvss_score"].to_numpy(dtype=float)
    print(f"-> Data: {len(df)} entri, matriks TF-IDF {X.shape}")

    kf = KFold(n_splits=5, shuffle=True, random_state=42)
    folds, cm_total, fold_times = [], np.zeros((5, 5), dtype=int), []
    agg = {"rounded": [], "legacy": [], "regression": []}
    for i, (tr, te) in enumerate(kf.split(X), start=1):
        model = RandomForestRegressor(
            n_estimators=rf_params.get("n_estimators", 100),
            criterion=rf_params.get("criterion", "squared_error"),
            max_depth=rf_params.get("max_depth", None),
            random_state=42, n_jobs=-1,
        )
        t0 = time.time()
        model.fit(X[tr], y[tr])
        fold_times.append(time.time() - t0)
        pred = np.clip(model.predict(X[te]), 0.0, 10.0)

        reg = {"mae": mean_absolute_error(y[te], pred),
               "rmse": float(np.sqrt(mean_squared_error(y[te], pred))),
               "r2_score": r2_score(y[te], pred)}
        rounded, t_lbl, p_lbl = classification_metrics(y[te], pred, severity_rounded)
        legacy, _, _ = classification_metrics(y[te], pred, severity_legacy)
        cm_total += confusion_matrix(t_lbl, p_lbl, labels=LABELS)
        agg["rounded"].append(rounded)
        agg["legacy"].append(legacy)
        agg["regression"].append(reg)
        folds.append({"fold": i, "train": int(len(tr)), "test": int(len(te)),
                      **{k: round(float(v), 4) for k, v in {**rounded, **reg}.items()},
                      "legacy_accuracy": round(float(legacy["accuracy"]), 4),
                      "training_time": round(fold_times[-1], 2)})
        print(f"   Fold {i}/5: acc={rounded['accuracy']:.4f} (lama {legacy['accuracy']:.4f}) "
              f"MAE={reg['mae']:.4f} R2={reg['r2_score']:.4f} ({fold_times[-1]:.1f} s)")

    mean = lambda key, part: float(np.mean([d[key] for d in agg[part]]))
    result = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "procedure": "KFold(5, shuffle=True, random_state=42); TF-IDF production; kelas dari skor dibulatkan 2 desimal",
        "n_samples": int(len(df)),
        "hyperparameters": rf_params,
        "metrics": {
            "accuracy": mean("accuracy", "rounded"), "precision": mean("precision", "rounded"),
            "recall": mean("recall", "rounded"), "f1_score": mean("f1_score", "rounded"),
            "mae": round(mean("mae", "regression"), 4), "rmse": round(mean("rmse", "regression"), 4),
            "r2_score": round(mean("r2_score", "regression"), 4),
            "training_time_seconds": round(float(np.sum(fold_times)), 2),
        },
        "legacy_binning_metrics": {k: mean(k, "legacy") for k in ("accuracy", "precision", "recall", "f1_score")},
        "confusion_matrix_labels": LABELS,
        "confusion_matrix_all_folds": cm_total.tolist(),
        "folds": folds,
    }
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"-> Hasil ditulis ke {OUTPUT_PATH}")
    print(json.dumps({"metrics": result["metrics"], "legacy": result["legacy_binning_metrics"]}, indent=2))

    if args.sync_db:
        sys.path.insert(0, PROJECT_ROOT)
        from backend.core.settings import get_settings
        from backend.db.bootstrap import init_database
        from backend.db.session import session_scope
        from backend.repositories import research as research_repo
        db_url = get_settings().database_url
        init_database(db_url)
        with session_scope(db_url) as session:
            current = research_repo.load_model_evaluation(session) or {}
            research_repo.save_model_evaluation(session, {
                "algorithm": "Random Forest Regressor", **result["metrics"],
                "confusion_matrix": result["confusion_matrix_all_folds"],
                "shap_features": current.get("top_contributing_features", {}),
            })
        print(f"-> Metrik diperbarui di basis data: {db_url}")


if __name__ == "__main__":
    main()
