# backend/model_loader.py
import os
import pickle
import shap
from backend.config import RF_MODEL_PATH, TFIDF_PATH, load_active_model_name

model = None
rf_model = None
tfidf = None
shap_explainer = None


def init_models():
    global model, rf_model, tfidf, shap_explainer

    # Tentukan model aktif yang dipilih
    active_engine = load_active_model_name()

    # Validasi keberadaan berkas model Random Forest aktif dan vectorizer TF-IDF
    if not os.path.exists(RF_MODEL_PATH):
        raise FileNotFoundError(f"File model aktif Random Forest tidak ditemukan di {RF_MODEL_PATH}")

    if not os.path.exists(TFIDF_PATH):
        raise FileNotFoundError(f"File TF-IDF tidak ditemukan di {TFIDF_PATH}")

    # Muat vectorizer TF-IDF
    with open(TFIDF_PATH, "rb") as f:
        tfidf = pickle.load(f)

    # Muat model biner Random Forest dari disk secara aman
    try:
        with open(RF_MODEL_PATH, "rb") as f:
            rf_model = pickle.load(f)
            model = rf_model
    except Exception as e:
        raise e

    # Inisialisasi SHAP Explainer secara otomatis memakai model Random Forest
    try:
        shap_explainer = shap.TreeExplainer(rf_model)
    except Exception as e:
        shap_explainer = shap.Explainer(rf_model, feature_names=tfidf.get_feature_names_out())


def models_loaded() -> bool:
    """True bila model RF dan vectorizer TF-IDF sudah berada di memori."""
    return rf_model is not None and tfidf is not None
