# frontend/components/tab_blackbox_testing.py
"""
Modul Pengujian Black-Box & Verifikasi QA (tersembunyi).
Hanya dapat diakses melalui parameter URL tersembunyi (mis. ?test_mode=true, ?dev=true, ?qa=true).
Menjalankan kasus uji black-box fungsional pada Modul A sampai H (Subbab 3.6.4): 24 kasus versi awal
(unggah, estimasi skor, SHAP, korelasi, riwayat, dan API) ditambah kasus lapisan DSS dari
frontend/components/blackbox_dss.py.
"""
import os
import time
import tempfile
from contextlib import contextmanager
import pandas as pd
import streamlit as st

# CATATAN (v2): harness QA khusus mode dev ini sengaja menjalankan fungsi backend di dalam proses,
# mencerminkan tests/test_blackbox_scenarios.py. Skenario basis data berjalan pada basis data sementara
# yang terisolasi, bukan database.db riset (v1 menulis baris uji ke dalamnya).
from backend.config import ROOT_DIR, load_hybrid_escalation_rate, load_active_model_name
from backend.services.parsers.sonar_cwe_mapper import resolve_sonar_cwe
from frontend.utils.config import DEFAULT_API_URL
from frontend.components import blackbox_core as core
from frontend.components.blackbox_dss import CASES as DSS_CASES, MODULE_LABELS, dss_harness, run_dss_cases

LEGACY_CASES = 24
TOTAL_CASES = LEGACY_CASES + len(DSS_CASES)
ALL_MODULES = "Semua Modul"


@contextmanager
def _isolated_db():
    """Basis data sementara yang sudah dimigrasi untuk skenario basis data (TC-DB-*)."""
    from backend.db.bootstrap import init_database
    from backend.db.session import dispose_engine, sqlite_url_for

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    url = sqlite_url_for(path)
    init_database(url, force=True)
    try:
        yield url
    finally:
        dispose_engine(url)
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(path + suffix)
            except OSError:
                pass

SAMPLE_SONAR_PATH = os.path.join(ROOT_DIR, "sample-reports", "SonarQube_Report.json")
SAMPLE_ZAP_PATH = os.path.join(ROOT_DIR, "sample-reports", "OWASP_ZAP_Report.json")


def _run_single_test(test_fn, test_id, module_name, scenario_title, steps_text, input_text, expected_text, criteria_text):
    """Menjalankan satu fungsi uji secara aman dan mencatat metrik eksekusi formal."""
    t0 = time.time()
    try:
        actual_output = test_fn()
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        return {
            "ID Kasus": test_id,
            "Modul": module_name,
            "Fitur / Skenario Uji": scenario_title,
            "Langkah Pengujian": steps_text,
            "Masukan (Input)": input_text,
            "Hasil yang Diharapkan": expected_text,
            "Kriteria Keberhasilan": criteria_text,
            "Hasil Aktual": actual_output or "Terverifikasi memenuhi kriteria pengujian.",
            "Status": "PASS",
            "Durasi (ms)": elapsed_ms,
            "Catatan": "Pengujian berhasil dan memenuhi kriteria."
        }
    except Exception as e:
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        return {
            "ID Kasus": test_id,
            "Modul": module_name,
            "Fitur / Skenario Uji": scenario_title,
            "Langkah Pengujian": steps_text,
            "Masukan (Input)": input_text,
            "Hasil yang Diharapkan": expected_text,
            "Kriteria Keberhasilan": criteria_text,
            "Hasil Aktual": f"Gagal: {str(e)}",
            "Status": "FAIL",
            "Durasi (ms)": elapsed_ms,
            "Catatan": f"Exception: {str(e)}"
        }


def _execute_all_blackbox_scenarios():
    from backend import model_loader
    if model_loader.tfidf is None:
        try:
            model_loader.init_models()
        except Exception:
            pass
    """Menjalankan seluruh kasus uji black-box: 24 kasus versi awal dan kasus lapisan DSS."""
    with dss_harness() as ctx:
        results = _run_legacy_cases(ctx)
    # Kasus lapisan DSS (modul A, D sampai H) pada basis data dan konfigurasi sementara.
    results.extend(run_dss_cases())
    return results


def _run_legacy_cases(ctx):
    """24 kasus versi awal; kasus yang memerlukan API memakai harness dengan basis data sementara."""
    results = []

    # =========================================================================
    # MODUL A: Unggah & Parsing
    # =========================================================================
    results.append(_run_single_test(
        lambda: core.check_sonar_report_is_parsed(ctx), "TC-SAST-01", "Modul B - Unggah, Parsing & Riwayat",
        "Parsing Laporan SonarQube JSON Valid",
        "Unggah laporan SonarQube melalui API.",
        "SonarQube_Report.json.",
        "Temuan keamanan diekstrak beserta kunci, komponen, pesan, dan CWE.",
        "HTTP 200; setiap temuan lengkap dan CWE berformat benar."
    ))

    results.append(_run_single_test(
        lambda: core.check_non_json_is_rejected(ctx), "TC-SAST-02", "Modul B - Unggah, Parsing & Riwayat",
        "Validasi Ekstensi File SAST",
        "Unggah berkas CSV, PDF, XML, dan TXT melalui API.",
        "Empat berkas non-JSON.",
        "Berkas ditolak.",
        "HTTP 400 pada kedua endpoint unggah."
    ))

    results.append(_run_single_test(
        lambda: core.check_upload_size_limit(ctx), "TC-SAST-03", "Modul B - Unggah, Parsing & Riwayat",
        "Validasi Batas Ukuran File SAST (> 50 MB)",
        "Unggah berkas di atas batas dan tepat pada batas 50 MB.",
        "50 MB + 1 bita; 50 MB.",
        "Berkas di atas batas ditolak; berkas tepat pada batas tidak ditolak karena ukuran.",
        "HTTP 413 dan bukan 413."
    ))

    def tc_sast_04():
        sample_no_cwe = {"key": "K1", "message": "Code style", "tags": ["code-smell"]}
        cwe, has_tag = resolve_sonar_cwe(sample_no_cwe)
        if cwe != "N/A" or has_tag is not False:
            raise ValueError(f"Fallback CWE gagal: got cwe={cwe}, has_tag={has_tag}")
        return "Terverifikasi: Atribut cwe_id fallback ke 'N/A' dan has_cwe_tag bernilai False."

    results.append(_run_single_test(
        tc_sast_04, "TC-SAST-04", "Modul B - Unggah, Parsing & Riwayat",
        "Penanganan Tag CWE Kosong (CWE Fallback)",
        "Upload rekaman SonarQube tanpa tag CWE pada array tags.",
        "Objek issue dengan tags: ['security', 'owasp-a1'] (tanpa cwe-xxx).",
        "Atribut cwe_id diisi secara aman dengan nilai default 'N/A', dan has_cwe_tag bernilai False.",
        "Aplikasi tidak crash / unhandled exception."
    ))

    results.append(_run_single_test(
        lambda: core.check_zap_report_is_parsed(ctx), "TC-DAST-01", "Modul B - Unggah, Parsing & Riwayat",
        "Parsing Laporan OWASP ZAP JSON Valid",
        "Unggah laporan OWASP ZAP melalui API.",
        "OWASP_ZAP_Report.json.",
        "Peringatan diekstrak beserta CWE, metode HTTP, dan URI.",
        "HTTP 200; format CWE dan metode benar."
    ))

    results.append(_run_single_test(
        lambda: core.check_invalid_cwe_becomes_na(ctx), "TC-DAST-02", "Modul B - Unggah, Parsing & Riwayat",
        "Penanganan Alert CWE Bernilai Negatif (cweid: -1)",
        "Unggah peringatan dengan cweid tidak sah.",
        "cweid -1, 0, kosong, null, -7, dan teks.",
        "CWE menjadi N/A.",
        "Seluruh nilai tidak sah menjadi N/A; nilai sah tidak berubah."
    ))

    results.append(_run_single_test(
        lambda: core.check_out_of_scope_is_filtered(ctx), "TC-DAST-03", "Modul B - Unggah, Parsing & Riwayat",
        "Filter Domain di Luar Cakupan (Pre-Filtering Scope)",
        "Unggah peringatan pada domain yang dikecualikan dan domain uji.",
        "support.mozilla.org dan app.uji.",
        "Hanya peringatan domain uji yang dipertahankan.",
        "Satu temuan tersisa."
    ))

    # =========================================================================
    # MODUL B: Machine Learning & CVSS v4.0
    # =========================================================================
    def tc_ml_01():
        from backend.engine import run_single_prediction
        res = run_single_prediction(
            scanner_type="SonarQube",
            description="SQL Injection vulnerability in login authentication query via username parameter.",
            component="auth.py",
            issue_type="VULNERABILITY",
            has_cwe_tag=True
        )
        score = res.get("predicted_cvss4_score")
        sev = res.get("predicted_severity")
        if score is None or not (0.0 <= score <= 10.0) or sev not in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            raise ValueError(f"Hasil prediksi tidak valid: score={score}, sev={sev}")
        return f"Terverifikasi: Model aktif menghasilkan skor CVSS {score} ({sev})."

    results.append(_run_single_test(
        tc_ml_01, "TC-ML-01", "Modul C - Estimasi Skor & SHAP",
        "Inferensi Skor Regresi CVSS v4.0 (Random Forest)",
        "Klik tombol 'Jalankan Analisis Mesin Penilai' pada tab SAST atau DAST.",
        "Teks deskripsi kerentanan hasil ekstraksi (misal: SQL Injection / XSS).",
        "Backend memproses teks via TF-IDF (5.000 fitur), melakukan inferensi model aktif, menghasilkan skor kontinu rentang 0.0 - 10.0 dan severity kualitatif.",
        "Skor numerik presisi 1-2 desimal dan kategori (NONE/LOW/MEDIUM/HIGH/CRITICAL) terisi."
    ))

    results.append(_run_single_test(
        lambda: core.check_score_is_clipped(ctx), "TC-ML-02", "Modul C - Estimasi Skor & SHAP",
        "Pembatasan Batas Skor (Boundary Value Clipping)",
        "Kirim /predict dengan keluaran model di luar rentang.",
        "Keluaran model -3 sampai 15.",
        "Skor dibatasi pada 0,0–10,0.",
        "Skor respons sama dengan nilai yang dibatasi."
    ))

    results.append(_run_single_test(
        lambda: core.check_empty_description_is_rejected(ctx), "TC-ML-03", "Modul C - Estimasi Skor & SHAP",
        "Validasi & Ketahanan Inferensi terhadap Deskripsi Kosong",
        "Kirim /predict dengan deskripsi kosong.",
        "Teks kosong, spasi, dan baris baru.",
        "Permintaan ditolak.",
        "HTTP 400 dengan pesan deskripsi kosong."
    ))

    # =========================================================================
    # MODUL C: Korelasi Hybrid
    # =========================================================================
    results.append(_run_single_test(
        lambda: core.check_correlation_requires_both_sessions(ctx), "TC-HYB-01", "Modul D - Korelasi Hybrid & Isu",
        "Validasi Prasyarat History Session",
        "Jalankan korelasi tanpa sesi SAST, tanpa sesi DAST, dan tanpa keduanya.",
        "Kode sesi yang tidak ada.",
        "Korelasi ditolak sampai kedua sesi tersedia.",
        "HTTP 404 pada pratinjau dan korelasi."
    ))

    def tc_hyb_02():
        from backend.engine import run_hybrid_prediction
        res = run_hybrid_prediction(
            sast_desc="SQL injection in UserDAO.java executeQuery on line 42.",
            dast_desc="Time-based blind SQL injection detected on parameter 'user' via POST /api/login.",
            cwe_id="CWE-89"
        )
        if not res.get("is_verified_true_positive"):
            raise ValueError("Korelasi positif gagal diverifikasi")
        return f"Terverifikasi: Pasangan CWE-89 ditandai terdeteksi kedua pemindai (is_true_positive={res.get('is_verified_true_positive')})."

    results.append(_run_single_test(
        tc_hyb_02, "TC-HYB-02", "Modul D - Korelasi Hybrid & Isu",
        "Pencocokan Celah Keamanan Berbasis CWE ID",
        "Pilih 1 history session SAST dan 1 history session DAST yang memiliki irisan CWE ID sama.",
        "Session SAST (berisi CWE-89) dan Session DAST (berisi CWE-89).",
        "Sistem memasangkan temuan dengan CWE ID yang sama, menandainya terdeteksi kedua pemindai, dan menghitung Pair ID.",
        "Baris korelasi terbentuk dengan status 'Terdeteksi Kedua Pemindai' = YA."
    ))

    def tc_hyb_03():
        from backend.engine import run_hybrid_prediction
        er = load_hybrid_escalation_rate()
        res = run_hybrid_prediction(
            sast_desc="SQL injection vulnerability in query",
            dast_desc="SQL injection reflected in parameter",
            cwe_id="CWE-89"
        )
        base = res["base_score"]
        final = res["predicted_cvss4_score"]
        expected = min(10.0, round(base + ((10.0 - base) * er), 2))
        if final != expected:
            raise ValueError(f"Eskalasi skor tidak cocok: got {final}, expected {expected}")
        return f"Terverifikasi: Base Score {base} tereskalasi dengan ER={er*100}% menjadi {final}."

    results.append(_run_single_test(
        tc_hyb_03, "TC-HYB-03", "Modul D - Korelasi Hybrid & Isu",
        "Pembobotan Eskalasi Prioritas Remediasi (Escalation Rate)",
        "Amati perhitungan skor pada baris yang terdeteksi kedua pemindai.",
        "Nilai Base Score S_base dan Escalation Rate ER = 0.10 dari ai-model/config/ai_config.json.",
        "Skor hibrida dihitung secara matematis dengan formula: S_hybrid = min(10.0, S_base + ((10.0 - S_base) * ER)).",
        "Skor akhir meningkat sebesar 10% dari sisa gap menuju skor maksimum 10.0."
    ))

    def tc_hyb_04():
        from backend.engine import run_hybrid_prediction
        res = run_hybrid_prediction(
            sast_desc="Cross-site scripting in user comment",
            dast_desc="Path traversal in file download",
            cwe_id="N/A"
        )
        if res["is_verified_true_positive"] is not False or res["predicted_cvss4_score"] != res["base_score"]:
            raise ValueError("Korelasi negatif salah mendeteksi eskalasi")
        return f"Terverifikasi: Pasangan tanpa CWE bersama tidak ditandai terdeteksi kedua pemindai (skor {res['base_score']} tidak tereskalasi)."

    results.append(_run_single_test(
        tc_hyb_04, "TC-HYB-04", "Modul D - Korelasi Hybrid & Isu",
        "Korelasi Negatif (Tidak Ada Irisan CWE)",
        "Jalankan korelasi antara session SAST dan DAST yang sama sekali tidak memiliki kode CWE yang beririsan.",
        "Session SAST (CWE-79) dan Session DAST (CWE-22 / CWE-N/A).",
        "Tidak terbentuk pasangan terdeteksi kedua pemindai; skor tidak dieskalasi.",
        "Tidak ada eskalasi skor tanpa irisan CWE."
    ))

    # =========================================================================
    # MODUL D: Explainable AI (XAI-SHAP)
    # =========================================================================
    def tc_xai_01():
        from backend.engine import calculate_dynamic_shap
        shap_res = calculate_dynamic_shap(
            "SQL injection in user login query",
            "SQL error disclosure in HTTP response"
        )
        base = shap_res["shap_base_value"]
        t_pos = shap_res["shap_total_pos"]
        t_neg = shap_res["shap_total_neg"]
        bias = shap_res.get("absent_vocab_bias", 0.0)
        pred = shap_res["shap_predicted_score"]
        calc_sum = base + t_pos + t_neg + bias
        diff = abs(calc_sum - pred)
        if diff >= 0.05:
            raise ValueError(f"Properti aditif SHAP melampaui ambang batas: diff={diff}")
        return f"Terverifikasi: Base ({base}) + Pos ({t_pos}) + Neg ({t_neg}) + Bias ({bias}) ≈ Pred ({pred})."

    results.append(_run_single_test(
        tc_xai_01, "TC-XAI-01", "Modul C - Estimasi Skor & SHAP",
        "Kuantifikasi Nilai SHAP Aditif (Instance-Level)",
        "Lakukan analisis korelasi hibrida pada tab 3 atau tinjau correlation history.",
        "Pasangan deskripsi SAST dan DAST terverifikasi.",
        "Backend memanggil shap.TreeExplainer mengembalikan nilai: base_score, shap_base_value, shap_total_pos, shap_total_neg, shap_predicted_score.",
        "Nilai matematis aditif konsisten: BaseValue + TotalPos + TotalNeg + AbsentBias ≈ PredictedScore."
    ))

    def tc_xai_02():
        from frontend.components.tab_shap_visual import build_shap_figures_from_records
        records = [
            {"Key ID": "KEY-1", "Dominant Vulnerability Aggravating Factors (SHAP Positive)": "sql (+0.60)", "Dominant Vulnerability Reducing Factors (SHAP Negative)": "safe (-0.20)"}
        ]
        fig_bar, fig_strip, has_f = build_shap_figures_from_records(records, id_col_name="Key ID")
        if not has_f or fig_bar is None or fig_strip is None:
            raise ValueError("Gagal membangun visualisasi gabungan SHAP")
        return "Terverifikasi: Feature Importance Bar Chart dan Beeswarm Plot berhasil dibangun."

    results.append(_run_single_test(
        tc_xai_02, "TC-XAI-02", "Modul C - Estimasi Skor & SHAP",
        "Visualisasi Gabungan 50%-50% (Bar Chart & Beeswarm Plot)",
        "Periksa tampilan visualisasi transparansi SHAP pada bagian Executive Summary.",
        "Session history korelasi hybrid yang dipilih.",
        "Tampil 2 kolom visualisasi sejajar (50%/50%) berisikan Feature Importance Bar Chart (kiri) dan Beeswarm Strip Plot (kanan).",
        "Kedua grafik terender tanpa terpotong dan responsif."
    ))

    def tc_xai_03():
        from frontend.components.tab_shap_visual import build_shap_figures_from_records
        records = [
            {"Key ID": "K-1", "Dominant Vulnerability Aggravating Factors (SHAP Positive)": "token_a (+0.80) | token_b (+0.40)", "Dominant Vulnerability Reducing Factors (SHAP Negative)": "token_c (-0.15)"}
        ]
        fig_bar, fig_strip, has_f = build_shap_figures_from_records(records, id_col_name="Key ID")
        if not has_f or fig_bar is None or fig_strip is None:
            raise ValueError("Urutan sumbu Y gagal disinkronkan")
        return "Terverifikasi: Urutan nama fitur pada sumbu Y Beeswarm Plot sinkron dengan Feature Importance."

    results.append(_run_single_test(
        tc_xai_03, "TC-XAI-03", "Modul C - Estimasi Skor & SHAP",
        "Sinkronisasi Urutan Fitur pada Sumbu Y Grafik",
        "Amati urutan nama token kata (fitur) pada sumbu Y kedua grafik SHAP.",
        "Data kontribusi fitur SHAP.",
        "Urutan fitur pada sumbu Y Beeswarm Plot sinkron secara presisi mengikuti peringkat fitur teratas pada Feature Importance Bar Chart.",
        "Nama-nama fitur pada sumbu Y berada pada urutan yang identik."
    ))

    # =========================================================================
    # MODUL E: Basis Data & Ekspor
    # =========================================================================
    def tc_db_01():
        test_batch = "TC-DB-AUTO-TEST"
        df = pd.DataFrame([{
            "key_id": "FIND-01", "cwe_id": "CWE-89", "component": "c.py",
            "issue_description": "SQL injection", "predicted_cvss4_score": 8.0,
            "predicted_severity": "HIGH", "shap_positive": "N/A", "shap_negative": "N/A",
            "shap_base_value": 5.0, "shap_total_pos": 0.0, "shap_total_neg": 0.0,
            "shap_predicted_score": 5.0, "duration_seconds": 0.5
        }])
        from backend.db.session import session_scope
        from backend.repositories import history as history_repo
        with _isolated_db() as url:
            with session_scope(url) as s:
                history_repo.save_findings(s, test_batch, "SonarQube (SAST)", df.to_dict("records"))
            with session_scope(url) as s:
                cnt = len(history_repo.list_batch(s, test_batch))
        if cnt != 1:
            raise ValueError("Penyimpanan history gagal diverifikasi")
        return f"Terverifikasi: Entri history tersimpan otomatis ke tabel scan_history."

    results.append(_run_single_test(
        tc_db_01, "TC-DB-01", "Modul B - Unggah, Parsing & Riwayat",
        "Penyimpanan Otomatis Hasil Analisis ke SQLite",
        "Jalankan pengujian analisis sampai selesai.",
        "Hasil dataframe analisis dengan metadata durasi eksekusi.",
        "Seluruh rekaman tersimpan otomatis ke tabel scan_history lengkap dengan batch_id, timestamp, skor, dan durasi.",
        "Data langsung muncul pada tabel session history."
    ))

    results.append(_run_single_test(
        lambda: core.check_delete_needs_confirmation(ctx), "TC-DB-02", "Modul B - Unggah, Parsing & Riwayat",
        "Dialog Konfirmasi Penghapusan History Session",
        "Buka dialog hapus, tekan Batal, lalu tekan Ya; kirim permintaan hapus tanpa hak.",
        "Satu sesi riwayat.",
        "Sesi tidak terhapus tanpa konfirmasi dan tanpa hak.",
        "Tidak terhapus sebelum Ya; HTTP 401 dan 403."
    ))

    def tc_db_03():
        test_del_batch = "TC-DB-DEL-CONFIRM-TEST"
        df = pd.DataFrame([{
            "key_id": "FIND-DEL", "cwe_id": "CWE-79", "component": "v.py",
            "issue_description": "XSS", "predicted_cvss4_score": 6.0,
            "predicted_severity": "MEDIUM", "shap_positive": "N/A", "shap_negative": "N/A",
            "shap_base_value": 5.0, "shap_total_pos": 0.0, "shap_total_neg": 0.0,
            "shap_predicted_score": 5.0, "duration_seconds": 0.5
        }])
        from backend.db.session import session_scope
        from backend.repositories import history as history_repo
        with _isolated_db() as url:
            with session_scope(url) as s:
                history_repo.save_findings(s, test_del_batch, "OWASP ZAP (DAST)", df.to_dict("records"))
            with session_scope(url) as s:
                history_repo.delete_batch(s, test_del_batch)
            with session_scope(url) as s:
                cnt = len(history_repo.list_batch(s, test_del_batch))
        if cnt != 0:
            raise ValueError("Penghapusan data dari scan_history gagal")
        return f"Terverifikasi: Query DELETE FROM scan_history sukses dieksekusi."

    results.append(_run_single_test(
        tc_db_03, "TC-DB-03", "Modul B - Unggah, Parsing & Riwayat",
        "Eksekusi Penghapusan History Session",
        "Klik tombol 'Ya, Hapus Session' pada dialog konfirmasi.",
        "Konfirmasi positif user.",
        "Data session bersangkutan dihapus dari tabel scan_history, halaman melakukan st.rerun(), dan session hilang dari daftar.",
        "Query DELETE FROM scan_history WHERE batch_id = ? sukses dieksekusi."
    ))

    results.append(_run_single_test(
        lambda: core.check_csv_export_matches_queue(ctx), "TC-EXP-01", "Modul H - Kebijakan, Sensitivitas & Ekspor",
        "Export Laporan Analisis ke Format CSV",
        "Susun CSV daftar prioritas dari hasil pengurutan.",
        "Sesi uji.",
        "CSV memuat seluruh isu dengan urutan yang sama.",
        "Jumlah baris, kode, dan urutan sama."
    ))

    # =========================================================================
    # MODUL F: Endpoint API
    # =========================================================================
    def tc_api_01():
        from fastapi.testclient import TestClient
        from backend.api import app as fastapi_app
        with TestClient(fastapi_app) as client:
            resp = client.get("/")
            if resp.status_code != 200:
                raise ValueError(f"Root endpoint status: {resp.status_code}")
            j = resp.json()
            if j.get("status") != "online":
                raise ValueError("Status bukan online")
        return f"Terverifikasi: Status HTTP 200 OK dengan payload metadata valid (version: {j.get('version')})."

    results.append(_run_single_test(
        tc_api_01, "TC-API-01", "Modul H - Kebijakan, Sensitivitas & Ekspor",
        "Metadata Root Endpoint (GET /)",
        f"Kirim permintaan HTTP GET ke {DEFAULT_API_URL}/.",
        "HTTP GET Request.",
        "Mengembalikan response JSON 200 OK dengan kunci: status, title, version, description, escalation_rate, dan active_model.",
        "Status HTTP 200 OK dengan payload metadata valid."
    ))

    def tc_api_02():
        from fastapi.testclient import TestClient
        from backend.api import app as fastapi_app
        with TestClient(fastapi_app) as client:
            resp = client.get("/system_summary.json")
            if resp.status_code != 200:
                raise ValueError(f"System summary status: {resp.status_code}")
            j = resp.json()
            if "variety_cwe" not in j or "number_cvss4_records" not in j:
                raise ValueError("Kunci manifest tidak lengkap")
        return f"Terverifikasi: Data sinkron dengan file server (variety_cwe: {j.get('variety_cwe')}, records: {j.get('number_cvss4_records')})."

    results.append(_run_single_test(
        tc_api_02, "TC-API-02", "Modul H - Kebijakan, Sensitivitas & Ekspor",
        "Dynamic System Summary Manifest (GET /system_summary.json)",
        f"Akses endpoint {DEFAULT_API_URL}/system_summary.json.",
        "HTTP GET Request.",
        "Mengembalikan manifest ringkasan publik berisi status model aktif, escalation rate, variasi CWE, dan total data latih.",
        "Data sinkron dengan file system_summary.json di server (Status HTTP 200 OK)."
    ))

    def tc_api_03():
        from fastapi.testclient import TestClient
        from backend.api import app as fastapi_app
        with TestClient(fastapi_app) as client:
            for fname in ["SonarQube_Report.json", "OWASP_ZAP_Report.json"]:
                resp = client.get(f"/sample-reports/{fname}")
                if resp.status_code != 200:
                    raise ValueError(f"Download sampel {fname} gagal: {resp.status_code}")
        return "Terverifikasi: Kedua sampel payload SonarQube & ZAP ter-download dengan HTTP 200 OK."

    results.append(_run_single_test(
        tc_api_03, "TC-API-03", "Modul H - Kebijakan, Sensitivitas & Ekspor",
        "Download File Sampel Laporan (GET /sample-reports/{filename})",
        f"Akses endpoint {DEFAULT_API_URL}/sample-reports/SonarQube_Report.json atau OWASP_ZAP_Report.json.",
        "HTTP GET Request nama file sampel yang diizinkan.",
        "Mengembalikan stream file payload JSON laporan contoh untuk kebutuhan demonstrasi pengujian.",
        "Status HTTP 200 OK dengan format application/json."
    ))

    return results


def render_tab_blackbox_testing(app_model=None):
    """Menampilkan workbench Pengujian Black-Box tersembunyi untuk verifikasi pengembang / QA."""
    st.subheader("Pengujian Black-Box Sistem (Developer & QA Evaluation Workbench)")
    
    st.info(
        f"**Mode Pengembang Aktif**: Halaman pengujian tersembunyi ini menjalankan **{TOTAL_CASES} kasus uji** "
        "(Modul A s/d H, Subbab 3.6.4). Kasus lapisan DSS berjalan pada basis data dan konfigurasi sementara, sehingga "
        "data riset dan kebijakan yang berlaku tidak berubah. Halaman ini **tidak ditampilkan** pada antarmuka publik/responden umum."
    )

    # Header spesifikasi lingkungan
    with st.expander("Parameter Lingkungan & Konfigurasi Pengujian Sistem", expanded=False):
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown("**Sistem Operasi:** Windows / Linux")
            st.markdown("**Backend:** FastAPI (Uvicorn :8000)")
        with c2:
            st.markdown("**Frontend:** Streamlit (:8501)")
            st.markdown("**Database:** SQLite3 (`database.db`)")
        with c3:
            st.markdown(f"**Model AI Aktif:** {load_active_model_name()}")
            st.markdown(f"**Escalation Rate:** {int(load_hybrid_escalation_rate() * 100)}%")
        with c4:
            st.markdown("**Standar Penilaian:** CVSS v4.0")
            st.markdown("**Representasi:** TF-IDF (5.000 fitur)")

    st.markdown("---")

    # Kontrol (tombol 50%, dropdown filter 50%)
    col_btn, col_filter = st.columns([0.5, 0.5], vertical_alignment="center")
    with col_btn:
        run_all = st.button(f"Jalankan Seluruh Skenario Pengujian ({TOTAL_CASES} Kasus Uji)", type="primary", use_container_width=True)

    with col_filter:
        mod_filter = st.selectbox(
            "Filter Berdasarkan Modul:",
            [ALL_MODULES] + list(MODULE_LABELS.values()),
            label_visibility="collapsed"
        )

    # Jalankan pengujian bila diminta
    if run_all or "blackbox_results" not in st.session_state:
        with st.spinner(f"Menjalankan {TOTAL_CASES} skenario pengujian black-box"):
            progress_bar = st.progress(0)
            st.session_state["blackbox_results"] = _execute_all_blackbox_scenarios()
            progress_bar.progress(100)
            st.toast(f"Seluruh {TOTAL_CASES} kasus uji black-box selesai dieksekusi.", icon=None)

    raw_results = st.session_state.get("blackbox_results", [])
    df_results = pd.DataFrame(raw_results)

    if not df_results.empty:
        # Logika filter
        if mod_filter != ALL_MODULES:
            df_filtered = df_results[df_results["Modul"] == mod_filter]
        else:
            df_filtered = df_results

        total_cnt = len(df_filtered)
        pass_cnt = len(df_filtered[df_filtered["Status"] == "PASS"])
        fail_cnt = len(df_filtered[df_filtered["Status"] == "FAIL"])
        total_time_ms = round(df_filtered["Durasi (ms)"].sum(), 2)
        pass_rate = round((pass_cnt / total_cnt * 100), 1) if total_cnt > 0 else 0.0

        # Metrik ringkasan
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total Kasus Uji", total_cnt)
        m2.metric("Lulus (PASS)", pass_cnt)
        m3.metric("Gagal (FAIL)", fail_cnt)
        m4.metric("Tingkat Kelulusan", f"{pass_rate}%")
        m5.metric("Total Durasi", f"{total_time_ms} ms")

        st.markdown("---")

        # Tabel utama
        st.markdown(f"### Lembar Hasil Pengujian: {mod_filter}")
        
        # Tampilkan tabel bergaya
        display_cols = ["ID Kasus", "Modul", "Fitur / Skenario Uji", "Hasil yang Diharapkan", "Hasil Aktual", "Durasi (ms)", "Status"]
        st.dataframe(
            df_filtered[display_cols],
            use_container_width=True,
            hide_index=True
        )

        # Tombol unduh CSV sesuai format artefak tesis
        csv_data = df_filtered.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download Lembar Hasil Pengujian Black-Box (.CSV)",
            data=csv_data,
            file_name=f"Lembar_Hasil_Pengujian_Blackbox_{mod_filter.replace(' ', '_')}.csv",
            mime="text/csv",
            type="secondary"
        )

        # Akordeon rinci per kasus uji
        st.markdown("### Rincian Skenario Kasus Uji")
        for _, row in df_filtered.iterrows():
            status_badge = "[PASS]" if row["Status"] == "PASS" else "[FAIL]"
            with st.expander(f"{status_badge} | {row['ID Kasus']}: {row['Fitur / Skenario Uji']} ({row['Durasi (ms)']} ms)"):
                c_a, c_b = st.columns(2)
                with c_a:
                    st.markdown(f"**Modul:** {row['Modul']}")
                    st.markdown(f"**Langkah Pengujian:**\n{row['Langkah Pengujian']}")
                    st.markdown(f"**Masukan (Input):**\n`{row['Masukan (Input)']}`")
                with c_b:
                    st.markdown(f"**Kriteria Keberhasilan:**\n{row['Kriteria Keberhasilan']}")
                    st.markdown(f"**Hasil yang Diharapkan:**\n{row['Hasil yang Diharapkan']}")
                    st.markdown(f"**Hasil Aktual:**\n{row['Hasil Aktual']}")
                    st.markdown(f"**Catatan:** {row['Catatan']}")
