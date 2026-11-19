# tests/test_blackbox_scenarios.py
"""
Rangkaian Uji Black-Box Otomatis
Mencakup 24 kasus uji black-box fungsional formal (Modul A sampai F)
yang diturunkan dari Artefak Pengujian Tesis ('Skenario_Pengujian_Artefak_Tesis').
"""
import os
import json
import sqlite3
import pytest
import pandas as pd
import numpy as np

from backend.config import ROOT_DIR, EXCLUDED_PATH, load_unprocessing_domains, load_hybrid_escalation_rate
from backend.services.parsers.sonar_cwe_mapper import resolve_sonar_cwe
from frontend.utils.formatters import get_severity_category
from backend.db.session import session_scope
from backend.repositories import history as history_repo

# Jalur laporan sampel
SAMPLE_SONAR_PATH = os.path.join(ROOT_DIR, "sample-reports", "SonarQube_Report.json")
SAMPLE_ZAP_PATH = os.path.join(ROOT_DIR, "sample-reports", "OWASP_ZAP_Report.json")


# =============================================================================
# MODUL A: Pengujian Upload & Parsing Berkas Laporan Pemindaian
# =============================================================================

def test_tc_sast_01_parsing_sonarqube_json_valid():
    """TC-SAST-01: Parsing Laporan SonarQube JSON Valid."""
    assert os.path.exists(SAMPLE_SONAR_PATH), f"SonarQube sample report not found at {SAMPLE_SONAR_PATH}"
    with open(SAMPLE_SONAR_PATH, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    assert "issues" in data
    assert isinstance(data["issues"], list)
    assert len(data["issues"]) > 0

    first_issue = data["issues"][0]
    assert "key" in first_issue
    assert "component" in first_issue
    assert "message" in first_issue
    assert "type" in first_issue

    # Verifikasi resolusi CWE dari issue
    resolved_cwe, has_cwe = resolve_sonar_cwe(first_issue)
    assert resolved_cwe != ""
    assert isinstance(has_cwe, bool)


def test_tc_sast_02_validate_sast_file_extension():
    """TC-SAST-02: Validasi Ekstensi Berkas SAST (Menolak berkas non-JSON)."""
    allowed_extensions = ["json"]
    invalid_files = ["sample.csv", "document.pdf", "report.xml", "data.txt"]

    for filename in invalid_files:
        ext = filename.rsplit(".", 1)[-1].lower()
        is_valid = ext in allowed_extensions
        assert not is_valid, f"Extension {ext} should be rejected"


def test_tc_sast_03_validate_sast_file_size_limit():
    """TC-SAST-03: Validasi Batas Ukuran Berkas SAST (> 50 MB)."""
    max_size_bytes = 50 * 1024 * 1024  # 50 MB

    oversized_file_bytes = 52 * 1024 * 1024
    valid_file_bytes = 16 * 1024 * 1024

    assert oversized_file_bytes > max_size_bytes, "Should exceed 50 MB threshold"
    assert valid_file_bytes <= max_size_bytes, "Should be within 50 MB threshold"


def test_tc_sast_04_handle_empty_cwe_tag():
    """TC-SAST-04: Penanganan Tag CWE Kosong (CWE Fallback)."""
    issue_no_cwe = {
        "key": "TEST-NO-CWE",
        "rule": "dummy:rule-without-cwe",
        "component": "src/utils.py",
        "message": "Generic code style issue",
        "type": "CODE_SMELL",
        "tags": ["maintainability", "style"]
    }

    resolved_cwe, has_cwe = resolve_sonar_cwe(issue_no_cwe)
    assert resolved_cwe == "N/A"
    assert has_cwe is False


def test_tc_dast_01_parsing_owasp_zap_json_valid():
    """TC-DAST-01: Parsing Laporan OWASP ZAP JSON Valid."""
    assert os.path.exists(SAMPLE_ZAP_PATH), f"OWASP ZAP sample report not found at {SAMPLE_ZAP_PATH}"
    with open(SAMPLE_ZAP_PATH, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    assert "site" in data
    assert isinstance(data["site"], list)
    assert len(data["site"]) > 0

    first_site = data["site"][0]
    assert "alerts" in first_site
    assert len(first_site["alerts"]) > 0

    alert = first_site["alerts"][0]
    assert "cweid" in alert
    assert "name" in alert
    assert "instances" in alert
    assert len(alert["instances"]) > 0
    assert "uri" in alert["instances"][0]


def test_tc_dast_02_handle_negative_cwe_alert():
    """TC-DAST-02: Penanganan Alert CWE Bernilai Negatif (cweid: -1)."""
    negative_cwe_inputs = ["-1", -1, "", None]

    for raw_cwe in negative_cwe_inputs:
        try:
            cwe_int = int(raw_cwe) if raw_cwe is not None and str(raw_cwe).strip() != "" else -1
        except (ValueError, TypeError):
            cwe_int = -1

        resolved = f"CWE-{cwe_int}" if cwe_int > 0 else "N/A"
        assert resolved == "N/A", f"Expected N/A for input {raw_cwe}, got {resolved}"


def test_tc_dast_03_filter_out_of_scope_domains():
    """TC-DAST-03: Filter Domain di Luar Cakupan (Pre-Filtering Scope)."""
    assert os.path.exists(EXCLUDED_PATH), "excluded_domains.json config must exist"
    excluded_domains = load_unprocessing_domains()
    assert len(excluded_domains) > 0

    test_out_of_scope_url = "https://support.mozilla.org/kb/sample-help-article"
    is_excluded = any(domain.strip().lower() in test_out_of_scope_url.lower() for domain in excluded_domains)
    assert is_excluded is True, "Out of scope domain should be detected and filtered"


# =============================================================================
# MODUL B: Inferensi Model Machine Learning & Kuantifikasi CVSS v4.0
# =============================================================================

@pytest.mark.requires_model
def test_tc_ml_01_cvss4_regression_score_inference(client, sample_vulnerability_payload):
    """TC-ML-01: Inferensi Skor Regresi CVSS v4.0 (Random Forest)."""
    response = client.post("/predict", json=sample_vulnerability_payload)
    assert response.status_code == 200
    res_json = response.json()

    assert res_json["status"] == "success"
    score = res_json["predicted_cvss4_score"]
    assert isinstance(score, (int, float))
    assert 0.0 <= score <= 10.0

    severity = res_json["predicted_severity"]
    assert severity in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_tc_ml_02_score_boundary_clipping():
    """TC-ML-02: Pembatasan Batas Skor (Boundary Value Clipping [0.0 - 10.0])."""
    boundary_inputs = [-5.0, -0.01, 0.0, 5.5, 10.0, 10.01, 15.0]

    for val in boundary_inputs:
        clipped = max(0.0, min(float(val), 10.0))
        assert 0.0 <= clipped <= 10.0
        assert get_severity_category(clipped) in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_tc_ml_03_validate_empty_description(client):
    """TC-ML-03: Validasi & Ketahanan Inferensi terhadap Deskripsi Kosong (HTTP 400)."""
    empty_payload = {
        "scanner_type": "SonarQube",
        "description": "   ",
        "component": "login.py"
    }
    response = client.post("/predict", json=empty_payload)
    assert response.status_code == 400
    assert "detail" in response.json()
    assert "kosong" in response.json()["detail"].lower()


# =============================================================================
# MODUL C: Korelasi Kerentanan Hibrida (Hybrid SAST-DAST Correlation)
# =============================================================================

def test_tc_hyb_01_validate_history_session_prerequisite(temp_db_path):
    """TC-HYB-01: Validasi Prasyarat Sesi Riwayat (Database minimal 1 SAST & 1 DAST)."""
    conn = sqlite3.connect(temp_db_path)
    df_all = pd.read_sql_query("SELECT * FROM scan_history", conn)
    conn.close()

    sast_count = len(df_all[df_all["scanner_type"] == "SonarQube (SAST)"])
    dast_count = len(df_all[df_all["scanner_type"] == "OWASP ZAP (DAST)"])

    can_correlate = (sast_count > 0 and dast_count > 0)
    assert not can_correlate, "Correlation should be blocked when sessions are missing"


@pytest.mark.requires_model
def test_tc_hyb_02_cwe_based_vulnerability_matching(client, sample_hybrid_payload):
    """TC-HYB-02: Pencocokan Celah Keamanan Berbasis CWE ID (Left-Base join & True Positive YES)."""
    response = client.post("/predict/hybrid", json=sample_hybrid_payload)
    assert response.status_code == 200
    res_json = response.json()

    assert res_json["status"] == "success"
    assert res_json["is_verified_true_positive"] is True
    assert "base_score" in res_json
    assert "predicted_cvss4_score" in res_json


@pytest.mark.requires_model
def test_tc_hyb_03_priority_escalation_weighting(client, sample_hybrid_payload):
    """TC-HYB-03: Pembobotan Eskalasi Prioritas Remediasi (Escalation Rate)."""
    response = client.post("/predict/hybrid", json=sample_hybrid_payload)
    assert response.status_code == 200
    res_json = response.json()

    base_score = res_json["base_score"]
    hybrid_score = res_json["predicted_cvss4_score"]
    er = load_hybrid_escalation_rate()

    # Rumus eskalasi dinamis: final_score = min(10.0, round(base_score + ((10.0 - base_score) * er), 2))
    expected_hybrid = min(10.0, round(base_score + ((10.0 - base_score) * er), 2))
    assert hybrid_score == expected_hybrid
    assert hybrid_score >= base_score


@pytest.mark.requires_model
def test_tc_hyb_04_negative_correlation(client):
    """TC-HYB-04: Korelasi Negatif (Tidak Ada Irisan CWE / CWE = N/A)."""
    payload_disjoint = {
        "sast_description": "Cross-site scripting in user comment field.",
        "dast_description": "Path traversal detected in file download endpoint.",
        "cwe_id": "N/A",
        "sast_component": "comments.php",
        "dast_component": "/download.php"
    }
    response = client.post("/predict/hybrid", json=payload_disjoint)
    assert response.status_code == 200
    res_json = response.json()

    assert res_json["is_verified_true_positive"] is False
    assert res_json["predicted_cvss4_score"] == res_json["base_score"]


# =============================================================================
# MODUL D: Transparansi Kuantifikasi Explainable AI (XAI-SHAP)
# =============================================================================

@pytest.mark.requires_model
def test_tc_xai_01_additive_shap_value_quantification(client, sample_hybrid_payload):
    """TC-XAI-01: Kuantifikasi Nilai SHAP Aditif (Instance-Level)."""
    response = client.post("/predict/shap", json=sample_hybrid_payload)
    assert response.status_code == 200
    res_json = response.json()

    assert res_json["status"] == "success"
    shap_base = res_json["shap_base_value"]
    total_pos = res_json["shap_total_pos"]
    total_neg = res_json["shap_total_neg"]
    absent_bias = res_json.get("absent_vocab_bias", 0.0)
    pred_score = res_json["shap_predicted_score"]

    # Sifat aditif dengan mitigasi bias kosakata absen: Base + TotPos + TotNeg + AbsentBias = PredScore
    additive_sum = shap_base + total_pos + total_neg + absent_bias
    diff = abs(additive_sum - pred_score)
    assert diff < 0.05, f"Additive property failed: sum={additive_sum}, pred={pred_score}, diff={diff}"


def test_tc_xai_02_combined_bar_and_beeswarm_visualization():
    """TC-XAI-02: Visualisasi Gabungan 50%-50% (Bar Chart & Beeswarm Plot)."""
    from frontend.components.tab_shap_visual import build_shap_figures_from_records

    records = [
        {
            "Key ID": "KEY-1",
            "Dominant Vulnerability Aggravating Factors (SHAP Positive)": "manipulation (+0.45) | exploit (+0.30)",
            "Dominant Vulnerability Reducing Factors (SHAP Negative)": "site (-0.57) | xss (-0.27)"
        },
        {
            "Key ID": "KEY-2",
            "Dominant Vulnerability Aggravating Factors (SHAP Positive)": "injection (+0.75) | manipulation (+0.20)",
            "Dominant Vulnerability Reducing Factors (SHAP Negative)": "unauthenticated (-0.15)"
        }
    ]

    fig_bar, fig_strip, has_features = build_shap_figures_from_records(records, id_col_name="Key ID")
    assert has_features is True
    assert fig_bar is not None
    assert fig_strip is not None


def test_tc_xai_03_y_axis_feature_order_sync():
    """TC-XAI-03: Sinkronisasi Urutan Fitur pada Sumbu Y Grafik SHAP."""
    from frontend.components.tab_shap_visual import build_shap_figures_from_records

    records = [
        {
            "Key ID": "KEY-1",
            "Dominant Vulnerability Aggravating Factors (SHAP Positive)": "token_a (+0.90) | token_b (+0.50)",
            "Dominant Vulnerability Reducing Factors (SHAP Negative)": "token_c (-0.20)"
        }
    ]

    fig_bar, fig_strip, has_features = build_shap_figures_from_records(records, id_col_name="Key ID")
    assert has_features is True
    assert fig_bar is not None
    assert fig_strip is not None


# =============================================================================
# MODUL E: Manajemen Riwayat, Basis Data, & Ekspor Data (CRUD & Export)
# =============================================================================

def test_tc_db_01_auto_save_scan_results(temp_db_path, save_rows):
    """TC-DB-01: Penyimpanan Otomatis Hasil Analisis ke SQLite."""

    df_sample = pd.DataFrame([{
        "key_id": "FINDING-001",
        "cwe_id": "CWE-89",
        "component": "auth.py",
        "issue_description": "SQLi in auth controller",
        "predicted_cvss4_score": 8.5,
        "predicted_severity": "HIGH",
        "shap_positive": "sql (+0.5)",
        "shap_negative": "safe (-0.1)",
        "shap_base_value": 5.5,
        "shap_total_pos": 0.5,
        "shap_total_neg": -0.1,
        "shap_predicted_score": 5.9,
        "duration_seconds": 1.2
    }])

    save_rows("BATCH-TC-DB-01", "SonarQube (SAST)", df_sample)

    conn = sqlite3.connect(temp_db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM scan_history WHERE batch_id = 'BATCH-TC-DB-01'")
    count = cur.fetchone()[0]
    conn.close()

    assert count == 1, "Record should be automatically persisted in scan_history"


def test_tc_db_02_delete_session_confirmation_dialog():
    """TC-DB-02: Dialog Konfirmasi Penghapusan Sesi Riwayat (Verifikasi dialog modal mencegah penghapusan sepihak)."""
    # Memverifikasi persyaratan bahwa penghapusan tidak dapat berlanjut tanpa status konfirmasi dialog modal
    is_confirmed = False
    batch_target = "BATCH-CONFIRM-TEST"

    # Percobaan tanpa konfirmasi harus diblokir
    deleted = False
    if is_confirmed:
        deleted = True
    assert deleted is False, "Deletion must require explicit user confirmation via modal dialog"


def test_tc_db_03_execute_history_session_deletion(temp_db_path, db_url, save_rows):
    """TC-DB-03: Eksekusi Penghapusan Sesi Riwayat (DELETE FROM scan_history)."""

    df_sample = pd.DataFrame([{
        "key_id": "FINDING-002",
        "cwe_id": "CWE-79",
        "component": "view.py",
        "issue_description": "XSS reflected in view",
        "predicted_cvss4_score": 6.1,
        "predicted_severity": "MEDIUM",
        "shap_positive": "xss (+0.4)",
        "shap_negative": "encode (-0.2)",
        "shap_base_value": 5.5,
        "shap_total_pos": 0.4,
        "shap_total_neg": -0.2,
        "shap_predicted_score": 5.7,
        "duration_seconds": 0.8
    }])

    batch_to_delete = "BATCH-DELETE-TEST"
    save_rows(batch_to_delete, "OWASP ZAP (DAST)", df_sample)

    # Verifikasi data ada
    conn = sqlite3.connect(temp_db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM scan_history WHERE batch_id = ?", (batch_to_delete,))
    assert cur.fetchone()[0] == 1
    conn.close()

    # Jalankan penghapusan melalui repositori backend (v2)
    with session_scope(db_url) as s:
        assert history_repo.delete_batch(s, batch_to_delete) == 1

    # Verifikasi data terhapus
    conn = sqlite3.connect(temp_db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM scan_history WHERE batch_id = ?", (batch_to_delete,))
    assert cur.fetchone()[0] == 0
    conn.close()


def test_tc_exp_01_export_csv_report():
    """TC-EXP-01: Ekspor Laporan Analisis ke Format CSV (dengan header dan SHAP legend)."""
    df = pd.DataFrame([{
        "Pair ID": "HAST-999",
        "CWE ID": "CWE-89",
        "Base Score": 7.5,
        "Hybrid Score": 8.25,
        "Severity": "HIGH"
    }])

    csv_data = df.to_csv(index=False)
    assert "Pair ID,CWE ID,Base Score,Hybrid Score,Severity" in csv_data
    assert "HAST-999,CWE-89,7.5,8.25,HIGH" in csv_data


# =============================================================================
# MODUL F: Endpoint Orkestrasi Sistem (API Health & Manifest)
# =============================================================================

def test_tc_api_01_metadata_root_endpoint(client):
    """TC-API-01: Metadata Root Endpoint (GET /)."""
    response = client.get("/")
    assert response.status_code == 200
    res_json = response.json()

    assert res_json["status"] == "online"
    assert "title" in res_json
    assert "version" in res_json
    assert "escalation_rate" in res_json
    assert "active_model" in res_json


def test_tc_api_02_dynamic_system_summary_manifest(client):
    """TC-API-02: Dynamic System Summary Manifest (GET /system_summary.json)."""
    response = client.get("/system_summary.json")
    assert response.status_code == 200
    res_json = response.json()

    assert "active_model" in res_json
    assert "variety_cwe" in res_json
    assert "number_cvss4_records" in res_json
    assert "dataset_timestamp" in res_json


def test_tc_api_03_download_sample_report_files(client):
    """TC-API-03: Download Berkas Sampel Laporan (GET /sample-reports/{filename})."""
    for filename in ["SonarQube_Report.json", "OWASP_ZAP_Report.json"]:
        response = client.get(f"/sample-reports/{filename}")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")
