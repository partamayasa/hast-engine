# tests/test_database.py
# v2: menargetkan repositori backend (frontend tidak lagi membuka SQLite).
# Nama tes dan asersi tidak berubah dari v1.0.0-tesis.
import sqlite3

import pandas as pd

from backend.db.session import session_scope
from backend.repositories import research as research_repo


def test_init_db_creates_tables(temp_db_path):
    """Memastikan inisialisasi basis data membuat seluruh tabel riset yang diperlukan."""
    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()

    expected_tables = [
        "scan_history",
        "dataset_metadata",
        "dataset_class_distribution",
        "model_evaluation_metrics",
        # tambahan v2
        "users",
        "dss_runs",
        "dss_decisions",
        "dss_decision_events",
        "alembic_version",
    ]
    for table in expected_tables:
        assert table in tables, f"Tabel {table} tidak ditemukan pada database."
    assert "sus_responses" not in tables


def test_save_and_load_dataset_metadata(db_url):
    """Menguji penyimpanan dan pemuatan metadata populasi dataset NVD."""
    meta_payload = {
        "total_samples": 34194,
        "train_samples": 27355,
        "test_samples": 6839,
        "train_ratio": 0.8,
        "test_ratio": 0.2,
        "mean_score": 6.185,
        "std_score": 2.340,
        "min_score": 0.0,
        "max_score": 10.0,
        "validation_scheme": "Train-Test Split (80:20)"
    }
    class_dist_payload = [
        {"severity": "MEDIUM", "count": 14563, "proportion": 42.59, "score_range": "4.0 - 6.9"},
        {"severity": "HIGH", "count": 10830, "proportion": 31.67, "score_range": "7.0 - 8.9"},
        {"severity": "LOW", "count": 5721, "proportion": 16.73, "score_range": "0.1 - 3.9"},
        {"severity": "CRITICAL", "count": 3020, "proportion": 8.83, "score_range": "9.0 - 10.0"},
        {"severity": "NONE", "count": 60, "proportion": 0.18, "score_range": "0.0"}
    ]

    with session_scope(db_url) as s:
        research_repo.save_dataset_metadata(s, meta_payload, class_dist_payload)

    with session_scope(db_url) as s:
        loaded_meta = research_repo.load_dataset_metadata(s)
        loaded_dist = research_repo.load_class_distribution(s)
    assert loaded_meta is not None
    assert loaded_meta["total_samples"] == 34194
    assert loaded_meta["train_samples"] == 27355
    assert loaded_meta["test_samples"] == 6839
    assert round(loaded_meta["mean_score"], 3) == 6.185

    assert len(loaded_dist) == 5
    severities = [item["Severity Level"] for item in loaded_dist]
    assert "MEDIUM" in severities
    assert "CRITICAL" in severities


def test_save_and_load_model_evaluation(db_url):
    """Menguji penyimpanan dan pemuatan metrik evaluasi model AI."""
    eval_payload = {
        "algorithm": "Random Forest Regressor",
        "accuracy": 0.6707,
        "precision": 0.4966,
        "recall": 0.4543,
        "f1_score": 0.4683,
        "mae": 1.0678,
        "rmse": 1.5076,
        "r2_score": 0.5848,
        "training_time_seconds": 40.84,
        "confusion_matrix": [
            [3015, 1634, 154, 91],
            [726, 9814, 1524, 312],
            [63, 2442, 5311, 394],
            [1, 409, 1334, 479]
        ],
        "top_contributing_features": {
            "site": 0.3521,
            "unauthenticated": 0.2345,
            "code": 0.1791
        }
    }

    with session_scope(db_url) as s:
        research_repo.save_model_evaluation(s, eval_payload)
    with session_scope(db_url) as s:
        loaded_eval = research_repo.load_model_evaluation(s, "Random Forest Regressor")
    assert loaded_eval is not None
    assert loaded_eval["algorithm"] == "Random Forest Regressor"
    assert round(loaded_eval["accuracy"], 4) == 0.6707
    assert round(loaded_eval["mae"], 4) == 1.0678
    assert len(loaded_eval["confusion_matrix"]) == 4
    assert "site" in loaded_eval["top_contributing_features"]
    assert loaded_eval["top_contributing_features"]["site"] == 0.3521


def test_save_to_history(temp_db_path, save_rows):
    """Menguji penyimpanan log riwayat pemindaian ke tabel scan_history."""
    df_sample = pd.DataFrame([{
        "key_id": "FINDING-001",
        "cwe_id": "CWE-89",
        "component": "LoginController.php",
        "issue_description": "User input concatenated directly to SQL query string.",
        "predicted_cvss4_score": 8.5,
        "predicted_severity": "HIGH"
    }])

    save_rows(batch_id="TEST-BATCH-001", scanner_type="SonarQube", data=df_sample, execution_duration=1.25)

    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT batch_id, key_id, cwe_id, predicted_score, predicted_severity FROM scan_history WHERE batch_id = 'TEST-BATCH-001'")
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == "TEST-BATCH-001"
    assert row[1] == "FINDING-001"
    assert row[2] == "CWE-89"
    assert row[3] == 8.5
    assert row[4] == "HIGH"


def test_save_to_history_with_dedicated_shap_columns(temp_db_path, save_rows):
    """Menguji penyimpanan metrik SHAP khusus ke kolom-kolom tersendiri di scan_history."""
    df_sample = pd.DataFrame([{
        "key_id": "FINDING-SHAP-01",
        "cwe_id": "CWE-79",
        "component": "vuln.php",
        "issue_description": "Cross-site scripting vulnerability.\n[BASE_SCORE]: 6.12\n[SHAP_PRED]: 5.65",
        "predicted_cvss4_score": 6.12,
        "predicted_severity": "MEDIUM",
        "base_score": 6.12,
        "shap_base_value": 6.23,
        "shap_total_pos": 0.49,
        "shap_total_neg": -1.59,
        "absent_vocab_bias": 0.52,
        "shap_predicted_score": 5.65,
        "shap_positive": "script (+0.49)",
        "shap_negative": "sanitize (-1.59)",
        "sast_description": "Cross-site scripting vulnerability.",
        "dast_description": "N/A"
    }])

    save_rows(batch_id="TEST-SHAP-BATCH", scanner_type="SonarQube (SAST)", data=df_sample, execution_duration=0.85)

    conn = sqlite3.connect(temp_db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT description, base_score, shap_base_value, shap_total_pos, shap_total_neg,
               absent_vocab_bias, shap_predicted_score, shap_positive, shap_negative, sast_description
        FROM scan_history WHERE batch_id = 'TEST-SHAP-BATCH'
    """)
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    # Deskripsi harus bersih dari tag metadata
    assert "[BASE_SCORE]" not in row[0]
    assert "[SHAP_PRED]" not in row[0]
    assert row[0] == "Cross-site scripting vulnerability."
    assert row[1] == 6.12
    assert row[2] == 6.23
    assert row[3] == 0.49
    assert row[4] == -1.59
    assert row[5] == 0.52
    assert row[6] == 5.65
    assert row[7] == "script (+0.49)"
    assert row[8] == "sanitize (-1.59)"
    assert row[9] == "Cross-site scripting vulnerability."


def test_legacy_v1_database_is_adopted_without_data_change(tmp_path):
    """Basis data buatan skema v1 bermigrasi ke v2 dengan baris lama tidak berubah."""
    from backend.db.bootstrap import init_database
    from backend.db.session import dispose_engine, sqlite_url_for

    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE scan_history (id INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT, timestamp TEXT, "
                 "scanner_type TEXT, key_id TEXT, cwe_id TEXT, component TEXT, description TEXT, "
                 "predicted_score REAL, predicted_severity TEXT)")
    conn.execute("INSERT INTO scan_history (batch_id, scanner_type, key_id, cwe_id, component, description, "
                 "predicted_score, predicted_severity) VALUES ('DAST-1', 'OWASP ZAP (DAST)', 'XSS', 'CWE-79', "
                 "'GET https://x', 'Reflected XSS\n[MITIGATION]: Encode output', 6.5, 'MEDIUM')")
    conn.commit()
    conn.close()

    url = sqlite_url_for(path)
    init_database(url, force=True)
    dispose_engine(url)

    conn = sqlite3.connect(path)
    row = conn.execute("SELECT key_id, predicted_score, description, mitigation_text, base_score FROM scan_history").fetchone()
    version = conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]
    conn.close()
    assert row[0] == "XSS" and row[1] == 6.5
    assert row[2] == "Reflected XSS\n[MITIGATION]: Encode output"
    assert row[3] == "Encode output"
    assert version == "0006_drop_sus_responses"


def test_sus_table_with_rows_is_kept_by_migration(tmp_path):
    """Revisi 0006 hanya menghapus sus_responses yang kosong; baris yang ada tidak boleh hilang."""
    from backend.db.bootstrap import init_database
    from backend.db.session import dispose_engine, sqlite_url_for

    path = tmp_path / "sus_lama.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE sus_responses (id INTEGER PRIMARY KEY, respondent_name TEXT)")
    conn.execute("INSERT INTO sus_responses (respondent_name) VALUES ('R01')")
    conn.commit()
    conn.close()
    url = sqlite_url_for(path)
    init_database(url, force=True)
    dispose_engine(url)
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT COUNT(*) FROM sus_responses").fetchone()[0] == 1
    assert conn.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0006_drop_sus_responses"
    conn.close()
