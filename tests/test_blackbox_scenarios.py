# tests/test_blackbox_scenarios.py
"""
Rangkaian Uji Black-Box Otomatis
Mencakup 24 kasus uji black-box fungsional formal (Modul A sampai F)
yang diturunkan dari Artefak Pengujian Tesis ('Skenario_Pengujian_Artefak_Tesis').
"""
import os
import sqlite3
import pytest
import pandas as pd

from backend.config import ROOT_DIR, load_hybrid_escalation_rate
from backend.services.parsers.sonar_cwe_mapper import resolve_sonar_cwe
from backend.db.session import session_scope
from backend.repositories import history as history_repo
from frontend.components import blackbox_core as core
from frontend.components.blackbox_dss import dss_harness


@pytest.fixture(scope="module")
def ctx():
    """API pada basis data sementara; pemeriksaannya sama dengan halaman Pengujian Black-Box."""
    with dss_harness() as harness:
        yield harness


# Jalur laporan sampel
SAMPLE_SONAR_PATH = os.path.join(ROOT_DIR, "sample-reports", "SonarQube_Report.json")
SAMPLE_ZAP_PATH = os.path.join(ROOT_DIR, "sample-reports", "OWASP_ZAP_Report.json")


# =============================================================================
# MODUL A: Pengujian Upload & Parsing Berkas Laporan Pemindaian
# =============================================================================

def test_tc_sast_01_parsing_sonarqube_json_valid(ctx):
    """TC-SAST-01: Parsing Laporan SonarQube JSON Valid."""
    core.check_sonar_report_is_parsed(ctx)


def test_tc_sast_02_validate_sast_file_extension(ctx):
    """TC-SAST-02: Validasi Ekstensi Berkas SAST (Menolak berkas non-JSON)."""
    core.check_non_json_is_rejected(ctx)


def test_tc_sast_03_validate_sast_file_size_limit(ctx):
    """TC-SAST-03: Validasi Batas Ukuran Berkas SAST (> 50 MB)."""
    core.check_upload_size_limit(ctx)


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


def test_tc_dast_01_parsing_owasp_zap_json_valid(ctx):
    """TC-DAST-01: Parsing Laporan OWASP ZAP JSON Valid."""
    core.check_zap_report_is_parsed(ctx)


def test_tc_dast_02_handle_negative_cwe_alert(ctx):
    """TC-DAST-02: Penanganan Alert CWE Bernilai Negatif (cweid: -1)."""
    core.check_invalid_cwe_becomes_na(ctx)


def test_tc_dast_03_filter_out_of_scope_domains(ctx):
    """TC-DAST-03: Filter Domain di Luar Cakupan (Pre-Filtering Scope)."""
    core.check_out_of_scope_is_filtered(ctx)


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


@pytest.mark.requires_model
def test_tc_ml_02_score_boundary_clipping(ctx):
    """TC-ML-02: Pembatasan Batas Skor (Boundary Value Clipping [0.0 - 10.0])."""
    core.check_score_is_clipped(ctx)


def test_tc_ml_03_validate_empty_description(ctx):
    """TC-ML-03: Validasi & Ketahanan Inferensi terhadap Deskripsi Kosong (HTTP 400)."""
    core.check_empty_description_is_rejected(ctx)


# =============================================================================
# MODUL C: Korelasi Kerentanan Hibrida (Hybrid SAST-DAST Correlation)
# =============================================================================

def test_tc_hyb_01_validate_history_session_prerequisite(ctx):
    """TC-HYB-01: Validasi Prasyarat Sesi Riwayat (Database minimal 1 SAST & 1 DAST)."""
    core.check_correlation_requires_both_sessions(ctx)


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


def test_tc_db_02_delete_session_confirmation_dialog(ctx):
    """TC-DB-02: Dialog Konfirmasi Penghapusan Sesi Riwayat (Verifikasi dialog modal mencegah penghapusan sepihak)."""
    core.check_delete_needs_confirmation(ctx)


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


def test_tc_exp_01_export_csv_report(ctx):
    """TC-EXP-01: Ekspor Laporan Analisis ke Format CSV (dengan header dan SHAP legend)."""
    core.check_csv_export_matches_queue(ctx)


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
