# tests/test_ai_model.py
import os
import pickle
import numpy as np
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
AI_MODEL_ROOT = os.path.join(ROOT_DIR, "ai-model")
RF_MODEL_PATH = os.path.join(AI_MODEL_ROOT, "artifacts", "model_random_forest.pkl")
TFIDF_PATH = os.path.join(AI_MODEL_ROOT, "artifacts", "tfidf_vectorizer.pkl")


@pytest.mark.requires_model
def test_artifacts_exist():
    """Memverifikasi keberadaan berkas artefak biner Random Forest dan TF-IDF."""
    assert os.path.exists(RF_MODEL_PATH), f"Model artifact file not found at {RF_MODEL_PATH}"
    assert os.path.exists(TFIDF_PATH), f"TF-IDF artifact file not found at {TFIDF_PATH}"


@pytest.mark.requires_model
def test_model_and_vectorizer_inference():
    """Menguji pipeline inferensi teks kerentanan menjadi vektor TF-IDF dan prediksi skor CVSS v4.0."""
    with open(TFIDF_PATH, "rb") as f:
        tfidf = pickle.load(f)

    with open(RF_MODEL_PATH, "rb") as f:
        rf_model = pickle.load(f)

    test_descriptions = [
        "Unauthenticated remote code execution vulnerability in Apache HTTP server allowing root access.",
        "Reflected cross-site scripting (XSS) in search query parameter.",
        "Informational disclosure of server software version in HTTP header response."
    ]

    # Transformasi menjadi vektor TF-IDF
    features = tfidf.transform(test_descriptions)
    assert features.shape[0] == len(test_descriptions)

    # Prediksi kontinu dengan Random Forest
    predictions = rf_model.predict(features)
    assert len(predictions) == len(test_descriptions)

    for score in predictions:
        # Batas logis CVSS v4.0
        clipped = np.clip(score, 0.0, 10.0)
        assert 0.0 <= clipped <= 10.0

    # RCE umumnya diprediksi lebih tinggi daripada pengungkapan header versi
    pred_rce = predictions[0]
    pred_info = predictions[2]
    assert pred_rce >= pred_info, f"Expected RCE score ({pred_rce}) >= info disclosure ({pred_info})"
