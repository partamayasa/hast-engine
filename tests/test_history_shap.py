# tests/test_history_shap.py
# v2: persistensi melalui repositori backend; pekerja grafik SHAP tetap di lapisan UI.
import sqlite3

import pandas as pd


def test_history_shap_generation_sast(temp_db_path, save_rows):
    df_sast = pd.DataFrame([{
        "key_id": "SQ-001",
        "cwe_id": "CWE-614",
        "component": "AutoLogin.php",
        "issue_description": "Make sure creating this cookie without the secure flag is safe here.",
        "predicted_cvss4_score": 6.78,
        "predicted_severity": "MEDIUM"
    }])

    save_rows("SAST-TEST-01", "SonarQube (SAST)", df_sast)

    conn = sqlite3.connect(temp_db_path)
    cur = conn.cursor()
    cur.execute("SELECT batch_id, scanner_type, predicted_score FROM scan_history WHERE batch_id = 'SAST-TEST-01'")
    row = cur.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == "SAST-TEST-01"
    assert row[1] == "SonarQube (SAST)"
    assert row[2] == 6.78


def test_history_shap_generation_dast(temp_db_path, save_rows):
    df_dast = pd.DataFrame([{
        "key_id": "Cross Site Scripting (XSS)",
        "cwe_id": "CWE-79",
        "component": "https://example.com/test",
        "issue_description": "Cross site scripting vulnerability in search query input.",
        "comment_solution": "Sanitize and escape all input.",
        "predicted_cvss4_score": 7.5,
        "predicted_severity": "HIGH"
    }])

    save_rows("DAST-TEST-01", "OWASP ZAP (DAST)", df_dast)

    conn = sqlite3.connect(temp_db_path)
    cur = conn.cursor()
    cur.execute("SELECT batch_id, scanner_type, predicted_score, description, mitigation_text "
                "FROM scan_history WHERE batch_id = 'DAST-TEST-01'")
    row = cur.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == "DAST-TEST-01"
    assert row[1] == "OWASP ZAP (DAST)"
    assert row[2] == 7.5
    assert "[MITIGATION]: Sanitize and escape all input." in row[3]
    # v2: teks mitigasi juga disimpan di kolom tersendiri
    assert row[4] == "Sanitize and escape all input."


def test_worker_compute_shap_and_cache():
    from frontend.components.history import (
        _worker_compute_shap,
        _SHAP_CACHE,
        _SHAP_LOCK,
        clear_shap_cache
    )

    clear_shap_cache()

    rows = [{
        "key_id": "PAIR-001",
        "cwe_id": "CWE-79",
        "component": "form.php",
        "predicted_score": 8.1,
        "predicted_severity": "HIGH",
        "description": "[SAST]: XSS in echo input\n[DAST]: XSS payload reflected in page\n[SHAP_POS]: echo (+0.85), input (+0.45)\n[SHAP_NEG]: sanitize (-0.30)\n[SHAP_BASE]: 5.50\n[SHAP_TOT_POS]: 1.30\n[SHAP_TOT_NEG]: -0.30\n[SHAP_PRED]: 6.50"
    }]

    cache_key = "TEST-BATCH-01_"
    _worker_compute_shap(cache_key, rows, is_hybrid=True, is_sast=False, is_dast=False, id_col_name="Pair ID")

    with _SHAP_LOCK:
        res = _SHAP_CACHE.get(cache_key)

    assert res is not None
    assert res.get("status") == "ready"
    assert res.get("has_features") is True
    assert res.get("fig_shap_hist") is not None
    assert "echo" in res.get("csv_data_hist_shap")

    clear_shap_cache("TEST-BATCH-01")
    with _SHAP_LOCK:
        assert cache_key not in _SHAP_CACHE
