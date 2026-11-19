# frontend/components/analysis_flow.py
import re
import pandas as pd
import plotly.express as px
import streamlit as st

from frontend.utils.formatters import get_severity_category
from frontend.utils.api_client import ApiError, create_batch
from frontend.components.history import load_cached_scan_history


def run_analysis_flow(scanner_label, prefix_batch, parsed_records, target_domain_input="", is_button_enabled=True):
    """Menangani alur evaluasi data masukan dan visualisasi grafik metrik akhir."""
    df_input = pd.DataFrame(parsed_records)
    if df_input.empty:
        st.error("Struktur JSON kosong atau tidak dapat diekstrak.")
        return
    st.success(f"Berhasil mengekstrak {len(df_input)} entri celah keamanan dari file JSON.")

    if st.button(f"Jalankan Analisis Mesin Penilai", type="primary", key=f"btn_engine_{prefix_batch}", disabled=not is_button_enabled):
        # v2: satu permintaan batch; backend menerapkan pra-penyaringan fast-path v1, memberi skor setiap
        # temuan, dan menyimpan sesi (sebelumnya ThreadPoolExecutor + penulisan SQLite langsung).
        with st.spinner("Memproses penilaian kerentanan"):
            try:
                result = create_batch(prefix_batch.upper(), df_input.to_dict("records"))
            except ApiError as e:
                st.error(f"Analisis gagal: {e}")
                st.stop()
        load_cached_scan_history.clear()

        scored = pd.DataFrame(result["records"])
        df_input['predicted_cvss4_score'] = scored['predicted_cvss4_score'].values
        df_input['predicted_severity'] = scored['predicted_severity'].values
        duration = float(result.get("execution_duration", 0.0))
        generated_batch_id = result["batch_id"]

        st.success(f"Selesai dalam {duration:.2f} detik! Hasil skoring disimpan dengan nama: **{generated_batch_id}**.")
        st.markdown("---")

        col1, col2 = st.columns([1, 1])
        with col1:
            st.subheader("Tabel Hasil Analisis Session Ini")
            df_active = df_input[df_input['predicted_severity'].str.upper() != 'NONE'].copy()
            df_table_source = df_active if not df_active.empty else df_input.copy()
            df_sorted = df_table_source.sort_values(by='predicted_cvss4_score', ascending=False)
            df_output_en = df_sorted[['key_id', 'cwe_id', 'predicted_cvss4_score',
                                      'predicted_severity', 'component']].copy().reset_index(drop=True)
            df_output_en.insert(0, 'No', df_output_en.index + 1)
            df_output_en.columns = ['No', 'Key ID', 'CWE ID', 'Predicted Score', 'Predicted Severity', 'Component']
            df_output_en['Predicted Score'] = df_output_en['Predicted Score'].map(lambda x: f"{x:.2f}")
            st.dataframe(df_output_en, width="stretch", hide_index=True)
        with col2:
            st.subheader("Diagram Sebaran Severity Level")
            col_graph, col_metric = st.columns([1.1, 0.9])
            with col_graph:
                severity_counts = df_input['predicted_severity'].value_counts().reset_index()
                severity_counts.columns = ['Severity', 'Count']
                color_map = {'CRITICAL': 'purple', 'HIGH': 'red', 'MEDIUM': 'orange', 'LOW': 'yellow', 'NONE': 'green'}
                fig = px.pie(severity_counts, values='Count', names='Severity',
                             color='Severity', color_discrete_map=color_map, hole=0.3)
                fig.update_layout(margin=dict(l=0, r=0, t=10, b=10), showlegend=False)
                st.plotly_chart(fig, width="stretch")
            with col_metric:
                df_metric_source = df_input[df_input['predicted_severity'].str.upper() != 'NONE']
                if df_metric_source.empty:
                    df_metric_source = df_input
                median_score = float(df_metric_source['predicted_cvss4_score'].median())
                max_score = float(df_input['predicted_cvss4_score'].max())
                total_cases = len(df_metric_source)
                critical_high_count = len(
                    df_input[df_input['predicted_severity'].str.upper().isin(['CRITICAL', 'HIGH'])])
                median_severity = get_severity_category(median_score)
                max_severity = get_severity_category(max_score)
                st.markdown("<div style='padding-top: 10px;'></div>", unsafe_allow_html=True)
                st.metric(
                    label="Skor Median (CVSS 4.0)",
                    value=f"{median_score:.2f}",
                    help="Nilai tengah (median) estimasi skor CVSS v4.0 dari seluruh temuan kerentanan. Menggambarkan severity level tipikal sistem yang lebih stabil dan tidak terdistorsi oleh temuan ekstrem (pencilan)."
                )
                st.markdown(
                    f"<p style='padding-top: 10px;'>Kategori: <b>{median_severity}</b></p>", unsafe_allow_html=True)
                st.markdown("<div style='padding-top: 15px;'></div>", unsafe_allow_html=True)
                st.metric(
                    label="Skor Kerentanan Tertinggi",
                    value=f"{max_score:.2f}",
                    help="Skor estimasi CVSS v4.0 tertinggi yang terdeteksi pada test session ini. Menandakan celah keamanan paling kritis yang berpotensi menimbulkan dampak risiko terbesar dan memerlukan prioritas penanganan utama."
                )
                st.markdown(
                    f"<p style='padding-top: 10px;'>Kategori: <b>{max_severity}</b></p>", unsafe_allow_html=True)
                unique_cwes_flow = []
                if 'cwe_id' in df_metric_source.columns:
                    for raw_cwe in df_metric_source['cwe_id'].dropna():
                        raw_str = str(raw_cwe).strip()
                        if not raw_str or raw_str.upper() in ['N/A', 'NONE', 'UNKNOWN', 'NULL', '0', '-1']:
                            continue
                        cwes_found = re.findall(r'CWE-\d+', raw_str, re.IGNORECASE)
                        if cwes_found:
                            for c in cwes_found:
                                if c.upper() not in unique_cwes_flow:
                                    unique_cwes_flow.append(c.upper())
                        else:
                            if raw_str.upper() not in [c.upper() for c in unique_cwes_flow]:
                                unique_cwes_flow.append(raw_str)

                    def _sort_cwe_key_f(cwe_val):
                        match = re.search(r'\d+', cwe_val)
                        return (0, int(match.group(0))) if match else (1, cwe_val)

                    unique_cwes_flow = sorted(unique_cwes_flow, key=_sort_cwe_key_f)

                help_total_flow = (
                    f"Mencakup {len(unique_cwes_flow)} CWE-ID: {', '.join(unique_cwes_flow)}"
                    if unique_cwes_flow else "Jumlah total temuan celah kerentanan"
                )

                st.metric(label="Total Temuan Celah", value=f"{total_cases}", help=help_total_flow)
                st.markdown("<div style='padding-top: 15px;'></div>", unsafe_allow_html=True)
                st.metric(label="Kerentanan Kritis & Tinggi", value=f"{critical_high_count}",
                          help="Jumlah celah kerentanan kategori Critical (9.0-10.0) & High (7.0-8.9)")
