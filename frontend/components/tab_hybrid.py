# frontend/components/tab_hybrid.py
"""
Halaman korelasi hybrid.

v2: pemasangan (irisan CWE Left-Base), skoring hybrid, dan persistensi berjalan di backend
(/api/v1/correlation/preview dan /run). Modul ini hanya menampilkan; label, metrik, dan kolom
tabel tidak berubah dari v1.0.0-tesis.
"""
import datetime
import re

import pandas as pd
import streamlit as st

from frontend.components.history import load_cached_scan_history, render_embedded_history
from frontend.components.tab_shap_visual import render_tab_shap_visual
from frontend.utils.api_client import ApiError, correlation_preview, correlation_run, list_batches
from frontend.utils.config import get_active_model

SAST_LABEL = "SonarQube (SAST)"
DAST_LABEL = "OWASP ZAP (DAST)"
HYBRID_LABEL = "Pengujian Korelasi Hybrid"


def batch_label(batch: dict) -> str:
    b_id = batch["batch_id"]
    date_str = ""
    if batch.get("timestamp"):
        try:
            date_str = pd.to_datetime(str(batch["timestamp"])).strftime("%Y/%m/%d %H:%M")
        except Exception:
            pass
    if not date_str and "-" in str(b_id):
        try:
            date_str = datetime.datetime.fromtimestamp(int(str(b_id).split("-")[-1])).strftime("%Y/%m/%d %H:%M")
        except Exception:
            pass
    return f"{b_id} ({date_str})" if date_str else str(b_id)


def unique_cwes(values) -> list[str]:
    found = []
    for raw in values:
        raw_str = str(raw).strip()
        if not raw_str or raw_str.upper() in ['N/A', 'NONE', 'UNKNOWN', 'NULL', '0', '-1']:
            continue
        cwes = re.findall(r'CWE-\d+', raw_str, re.IGNORECASE) or [raw_str]
        for c in cwes:
            if c.upper() not in [x.upper() for x in found]:
                found.append(c.upper())

    def _key(v):
        m = re.search(r'\d+', v)
        return (0, int(m.group(0))) if m else (1, v)
    return sorted(found, key=_key)


def _fmt(df, cols, na="N/A"):
    for c in cols:
        if c in df.columns:
            df[c] = df[c].map(lambda x: f"{float(x):.2f}" if pd.notna(x) else na)


def _render_dss_notice(dss: dict) -> None:
    """Menampilkan status pencatatan issue ke DSS setelah korelasi hybrid dijalankan."""
    if dss.get("recorded"):
        st.success(f"**{dss.get('issues', 0)} issue** langsung tercatat di DSS beserta rekomendasi prioritasnya. "
                   "Lihat di **Dashboard** atau **Prioritas Perbaikan**.")
    elif dss.get("reason") == "not_logged_in":
        st.info("Issue belum tercatat di DSS karena Anda belum login. Login dengan role Analis Keamanan, Manajer "
                "Keamanan, atau Administrator, lalu buka **Prioritas Perbaikan** untuk mencatatnya.")
    elif dss.get("reason") == "not_permitted":
        st.info("Role Anda tidak dapat mencatat issue ke DSS; hasil korelasi tetap tersimpan.")
    elif dss.get("reason") == "failed":
        st.warning(f"Hasil korelasi tersimpan, tetapi issue gagal dicatat di DSS: {dss.get('detail')}")


def render_results(records: list[dict], batch_id: str, app_model: str):
    df = pd.DataFrame(records)
    if df.empty:
        return
    res = pd.DataFrame({
        "Pair ID": df["key_id"],
        "CWE ID": df["cwe_id"],
        "SAST Case ID": df["sast_key_id"],
        "DAST Case ID": df["dast_key_id"],
        "Impacted Component": df["component"],
        "SAST Score": df["sast_score"],
        "DAST Score": df["dast_score"],
        "Hybrid Score": df["predicted_cvss4_score"],
        "Base Score": df["base_score"],
        "SHAP Base Value": df["shap_base_value"],
        "Total SHAP Positive": df["shap_total_pos"],
        "Total SHAP Negative": df["shap_total_neg"],
        "Absent Vocabulary Bias": df["absent_vocab_bias"],
        "SHAP Predicted Score": df["shap_predicted_score"],
        "Final Severity": df["predicted_severity"].str.upper(),
        "Verified True Positive": df["is_true_positive"].map(lambda v: "YES" if v else "NO"),
        "Dominant Vulnerability Aggravating Factors (SHAP Positive)": df["shap_positive"],
        "Dominant Vulnerability Reducing Factors (SHAP Negative)": df["shap_negative"],
    }).sort_values(by="Hybrid Score", ascending=False).reset_index(drop=True)

    st.markdown("### Ringkasan Eksekutif Analisis Kerentanan")
    m1, m2, m3, m4 = st.columns([1, 1, 1, 1])
    cwes = unique_cwes(res["CWE ID"].dropna())
    help_total = (f"Mencakup {len(cwes)} CWE-ID yang bersilangan: {', '.join(cwes)}" if cwes
                  else "Jumlah total temuan celah kerentanan")
    m1.metric(
        label="Skor Median (CVSS 4.0)", value=f"{float(res['Hybrid Score'].median()):.2f}",
        help="Nilai tengah (median) estimasi skor CVSS v4.0 Hybrid dari seluruh temuan kerentanan. Menggambarkan severity level tipikal sistem yang lebih stabil dan tidak terdistorsi oleh temuan ekstrem (pencilan)."
    )
    m2.metric(
        label="Skor Kerentanan Tertinggi", value=f"{float(res['Hybrid Score'].max()):.2f}",
        help="Skor estimasi CVSS v4.0 tertinggi yang terdeteksi pada test session ini. Menandakan celah keamanan paling kritis yang berpotensi menimbulkan dampak risiko terbesar dan memerlukan prioritas penanganan utama."
    )
    m3.metric("Total Temuan Celah", f"{len(res)}", help=help_total)
    m4.metric("Kerentanan Terverifikasi", f"{int((res['Verified True Positive'] == 'YES').sum())}",
              help="Jumlah celah terverifikasi True Positive pada SAST & DAST (pemicu eskalasi HAST)")

    st.markdown("---")
    st.markdown("### Laporan Akhir Analisis Kerentanan Kombinasi (CVSS 4.0 Hybrid)")
    st.success(
        f"Hasil skoring HAST & Manifest Data SHAP berhasil dikunci ke database dengan ID: **{batch_id}**. "
        "Silakan akses sub-bagian history di bawah untuk melakukan manajemen file laporan, atau buka halaman "
        "**Prioritas Perbaikan** untuk melihat issue yang harus ditangani lebih dulu."
    )

    res.insert(0, "No", res.index + 1)
    disp = res.copy()
    _fmt(disp, ["SAST Score", "DAST Score", "Hybrid Score", "Base Score", "SHAP Predicted Score", "SHAP Base Value"])
    _fmt(disp, ["Total SHAP Positive", "Total SHAP Negative", "Absent Vocabulary Bias"], na="0.00")

    def style_true_positive(val):
        color = '#ffcccc' if val == 'YES' else ''
        return f'background-color: {color}; color: black; font-weight: bold;'

    ui_columns = ['No', 'Pair ID', 'Final Severity', 'Hybrid Score', 'CWE ID',
                  'SAST Case ID', 'DAST Case ID', 'SAST Score', 'DAST Score', 'Verified True Positive']
    st.dataframe(disp[ui_columns].style.map(style_true_positive, subset=['Verified True Positive']),
                 width="stretch", hide_index=True)

    st.markdown("---")
    st.subheader("Transparansi Kuantifikasi Kerentanan (Analisis SHAP)")
    st.write("Tabel di bawah ini membedah kontribusi faktor metrik CVSS v4.0 dominan yang membentuk nilai prediksi model secara objektif untuk seluruh temuan terkorelasi.")
    ui_shap_columns = [
        'No', 'Pair ID', 'Final Severity', 'Hybrid Score', 'CWE ID', 'SAST Case ID', 'DAST Case ID',
        'SHAP Base Value', 'Total SHAP Positive', 'Total SHAP Negative', 'Absent Vocabulary Bias',
        'SHAP Predicted Score', 'Dominant Vulnerability Aggravating Factors (SHAP Positive)',
        'Dominant Vulnerability Reducing Factors (SHAP Negative)'
    ]
    st.dataframe(disp[ui_shap_columns], width="stretch", hide_index=True)
    active_model = app_model if app_model != "Unknown" else "Random Forest"
    st.caption(f"Siklus akuntabilitas: Fitur ini merepresentasikan aspek transparansi kuantifikasi tingkat lokal guna membedah justifikasi penilaian model {active_model} secara terukur.")


def render_tab_hybrid(app_model=None):
    """Menampilkan konten tab Pengujian Korelasi Hybrid."""
    if not app_model:
        app_model = get_active_model()

    st.subheader("Analisis Korelasi & Kerentanan Hybrid")
    st.write("Modul ini mencocokkan temuan **SonarQube (SAST)** and **OWASP ZAP (DAST)** berdasarkan kesamaan kode CWE untuk memastikan celah keamanan tersebut benar-benar aktif (True Positive).")

    try:
        sast_batches = list_batches(SAST_LABEL)
        dast_batches = list_batches(DAST_LABEL)
    except ApiError as e:
        st.error(f"Gagal memuat session dari backend: {e}")
        return

    if not sast_batches and not dast_batches:
        st.info("Database kosong. Lakukan proses upload dan analisis data di Tab SAST atau DAST terlebih dahulu.")
    elif not sast_batches or not dast_batches:
        st.warning("Diperlukan minimal masing-masing satu history session data SAST and data DAST di database untuk menjalankan korelasi")
    else:
        st.markdown("### Konfigurasi Test Session")
        by_id = {b["batch_id"]: b for b in sast_batches + dast_batches}
        col_sel1, col_sel2 = st.columns(2)
        with col_sel1:
            sel_sast = st.selectbox("Pilih Session SAST (Source Code):", [b["batch_id"] for b in sast_batches],
                                    format_func=lambda b: batch_label(by_id[b]))
        with col_sel2:
            sel_dast = st.selectbox("Pilih Session DAST (Runtime URL):", [b["batch_id"] for b in dast_batches],
                                    format_func=lambda b: batch_label(by_id[b]))

        try:
            pairs = correlation_preview(sel_sast, sel_dast)
        except ApiError as e:
            st.error(f"Gagal menghitung irisan CWE: {e}")
            pairs = []

        st.markdown("### Peta Irisan Celah Keamanan")
        if pairs:
            st.success(f"Deteksi Otomatis: Ditemukan {len(pairs)} celah keamanan dengan CWE ID beririsan!")
            df_preview = pd.DataFrame({
                "Pair ID": [p["pair_id"] for p in pairs],
                "CWE ID": [p["cwe_id"] for p in pairs],
                "SAST Case ID": [p["sast_key_id"] for p in pairs],
                "Initial SAST Score": [f"{p['initial_sast_score']:.2f}" for p in pairs],
                "DAST Case ID": [p["dast_key_id"] for p in pairs],
                "Initial DAST Score": [f"{p['initial_dast_score']:.2f}" for p in pairs],
                "Impacted Component": [f"{p['sast_component']} | {p['dast_component']}" for p in pairs],
            })
            df_preview.insert(0, "No", df_preview.index + 1)
            st.dataframe(df_preview, width="stretch", hide_index=True)
            st.caption("Pair ID pada preview bersifat sementara; ID final dibuat saat evaluasi dijalankan.")

            if st.button("Jalankan Evaluasi Korelasi Hybrid", type="primary"):
                with st.spinner("Memproses penilaian kerentanan hybrid"):
                    try:
                        result = correlation_run(sel_sast, sel_dast)
                    except ApiError as e:
                        st.error(f"Evaluasi korelasi gagal: {e}")
                        result = None
                if result and result.get("records"):
                    load_cached_scan_history.clear()
                    st.session_state["last_hybrid_batch"] = result["batch_id"]
                    _render_dss_notice(result.get("dss") or {})
                    render_results(result["records"], result["batch_id"], app_model)
        else:
            st.info("Tidak ditemukan irisan CWE ID yang sama pada kedua session batch ini. Kerentanan aplikasi cenderung terdistribusi secara terpisah (parsial).")

    render_embedded_history(HYBRID_LABEL, app_model=app_model)
    render_tab_shap_visual(app_model=app_model, scanner="HYBRID")
