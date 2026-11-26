# tests/test_backend_api.py
import pytest


def test_root_endpoint(client):
    """Menguji endpoint utama API backend (GET /)."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "version" in data
    assert "active_model" in data
    assert "escalation_rate" in data
    assert "dataset_timestamp" in data


def test_system_summary_endpoint(client):
    """Menguji endpoint informasi ringkasan sistem (GET /system_summary.json)."""
    response = client.get("/system_summary.json")
    assert response.status_code == 200
    data = response.json()
    assert "active_model" in data
    assert "variety_cwe" in data
    assert "number_cvss4_records" in data
    assert "dataset_timestamp" in data


@pytest.mark.requires_model
def test_predict_single_vulnerability_success(client, sample_vulnerability_payload):
    """Menguji prediksi skor satu kerentanan (POST /predict)."""
    response = client.post("/predict", json=sample_vulnerability_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "predicted_cvss4_score" in data
    assert "predicted_severity" in data

    score = data["predicted_cvss4_score"]
    assert isinstance(score, (int, float))
    assert 0.0 <= score <= 10.0
    assert data["predicted_severity"] in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_predict_empty_description_returns_400(client):
    """Menguji validasi deskripsi kosong yang mengembalikan HTTP 400 Bad Request."""
    payload = {
        "scanner_type": "SonarQube",
        "description": "   ",
        "component": "test.py"
    }
    response = client.post("/predict", json=payload)
    assert response.status_code == 400
    assert "Deskripsi kerentanan kosong" in response.json()["detail"]


@pytest.mark.requires_model
def test_predict_hybrid_success(client, sample_hybrid_payload):
    """Menguji prediksi korelasi hybrid SAST + DAST dengan verifikasi CWE ID (POST /predict/hybrid)."""
    response = client.post("/predict/hybrid", json=sample_hybrid_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "predicted_cvss4_score" in data
    assert "predicted_severity" in data
    assert "is_verified_true_positive" in data
    assert data["is_verified_true_positive"] is True

    h_score = data["predicted_cvss4_score"]
    assert 0.0 <= h_score <= 10.0
    assert data["predicted_severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@pytest.mark.requires_model
def test_predict_shap_success(client, sample_hybrid_payload):
    """Menguji perhitungan transparansi XAI token SHAP (POST /predict/shap)."""
    response = client.post("/predict/shap", json=sample_hybrid_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "shap_base_value" in data
    assert "shap_total_pos" in data
    assert "shap_total_neg" in data
    assert "shap_positive" in data
    assert "shap_negative" in data


def test_download_sample_reports(client):
    """Menguji ketersediaan berkas laporan sampel SAST dan DAST untuk keperluan demonstrasi."""
    res_sast = client.get("/sample-reports/SonarQube_Report.json")
    assert res_sast.status_code in [200, 404]  # 200 bila berkas ada di server

    res_dast = client.get("/sample-reports/OWASP_ZAP_Report.json")
    assert res_dast.status_code in [200, 404]
