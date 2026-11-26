# frontend/components/tab_shap_visual.py
import re
import datetime
import pandas as pd
import numpy as np
import plotly.express as px
import streamlit as st

from frontend.components.history import history_selectbox_key
from frontend.utils.config import get_active_model
from frontend.utils.api_client import ApiError, compute_history_shap, hit_shap_api, list_history

HISTORY_SCANNERS = ("SonarQube (SAST)", "OWASP ZAP (DAST)", "Pengujian Korelasi Hybrid")

# Cakupan tetap saat bagian SHAP disematkan di tab pemindai: kode -> (label riwayat, label tampilan).
SCANNER_SCOPES = {
    "SAST": ("SonarQube (SAST)", "SonarQube (SAST)"),
    "DAST": ("OWASP ZAP (DAST)", "OWASP ZAP (DAST)"),
    "HYBRID": ("Pengujian Korelasi Hybrid", "Pengujian Korelasi Hybrid (HAST)"),
}


def load_all_history(scanners=HISTORY_SCANNERS) -> pd.DataFrame:
    """Seluruh temuan tersimpan untuk pemindai terpilih, terbaru lebih dulu (v2: melalui API backend)."""
    frames = [list_history(s) for s in scanners]
    frames = [f for f in frames if not f.empty]
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True).sort_values("id", ascending=False).reset_index(drop=True)


def build_shap_figures_from_records(history_shap_report, id_col_name="Key ID"):
    """
    Membangun Feature Importance Bar Chart dan Beeswarm Plot dari laporan SHAP.
    Mengembalikan (fig_shap_hist, fig_beeswarm, has_features).
    """
    feature_scores = {}
    beeswarm_records = []

    for r_shap in history_shap_report:
        record_id = r_shap.get(id_col_name, "N/A")
        pos_str = str(r_shap.get("Dominant Vulnerability Aggravating Factors (SHAP Positive)", ""))
        neg_str = str(r_shap.get("Dominant Vulnerability Reducing Factors (SHAP Negative)", ""))

        pos_tokens = re.findall(r'([a-zA-Z0-9_\-]+)\s*\(\+?([\d\.]+)\)', pos_str)
        for token, val_str in pos_tokens:
            token_lower = token.strip()
            val = float(val_str)
            if token_lower not in feature_scores:
                feature_scores[token_lower] = []
            feature_scores[token_lower].append(val)
            beeswarm_records.append({
                id_col_name: record_id,
                "Kata Kunci (Token Teks)": token_lower,
                "Nilai SHAP": val,
                "Kategori Dampak": "Kontribusi Positif"
            })

        neg_tokens = re.findall(r'([a-zA-Z0-9_\-]+)\s*\(([\-\d\.]+)\)', neg_str)
        for token, val_str in neg_tokens:
            token_lower = token.strip()
            val = float(val_str)
            if val > 0:
                val = -val
            if token_lower not in feature_scores:
                feature_scores[token_lower] = []
            feature_scores[token_lower].append(abs(val))
            beeswarm_records.append({
                id_col_name: record_id,
                "Kata Kunci (Token Teks)": token_lower,
                "Nilai SHAP": val,
                "Kategori Dampak": "Kontribusi Negatif"
            })

    fig_shap_hist = None
    fig_beeswarm = None
    has_features = False

    if feature_scores:
        mean_feature_scores = {token: float(np.mean(vals)) for token, vals in feature_scores.items()}
        sorted_features = sorted(mean_feature_scores.items(), key=lambda x: x[1], reverse=True)[:10]

        if sorted_features:
            has_features = True
            top_feature_list = [f[0] for f in sorted_features]
            df_feat = pd.DataFrame({
                "Kata Kunci (Token Teks)": top_feature_list,
                "Tingkat Pengaruh (Mean |SHAP Value|)": [f[1] for f in sorted_features]
            }).sort_values(by="Tingkat Pengaruh (Mean |SHAP Value|)", ascending=True)

            max_val = df_feat["Tingkat Pengaruh (Mean |SHAP Value|)"].max()
            x_max = max_val * 1.18 if (pd.notna(max_val) and max_val > 0) else 1.0

            fig_shap_hist = px.bar(
                df_feat,
                x="Tingkat Pengaruh (Mean |SHAP Value|)",
                y="Kata Kunci (Token Teks)",
                orientation="h",
                text=df_feat["Tingkat Pengaruh (Mean |SHAP Value|)"].map(
                    lambda x: f"{x:.4f}" if pd.notna(x) else "0.0000"),
                color_discrete_sequence=["#1abc9c"]
            )
            order_list = df_feat["Kata Kunci (Token Teks)"].tolist()

            fig_shap_hist.update_traces(textposition="outside", cliponaxis=False)
            fig_shap_hist.update_layout(
                title="Feature Importance Bar Chart",
                margin=dict(l=20, r=60, t=40, b=20),
                height=380,
                xaxis_title="Kontribusi Rata-Rata Terhadap Prediksi (Mean |SHAP Value|)",
                yaxis_title="Fitur Kata Kunci Tekstual",
                xaxis=dict(range=[0, x_max]),
                yaxis=dict(categoryorder="array", categoryarray=order_list)
            )

            df_beeswarm = pd.DataFrame(beeswarm_records)
            if not df_beeswarm.empty:
                df_beeswarm = df_beeswarm[df_beeswarm["Kata Kunci (Token Teks)"].isin(top_feature_list)].copy()

                fig_beeswarm = px.strip(
                    df_beeswarm,
                    x="Nilai SHAP",
                    y="Kata Kunci (Token Teks)",
                    color="Kategori Dampak",
                    color_discrete_map={
                        "Kontribusi Positif": "#e74c3c",
                        "Kontribusi Negatif": "#3498db"
                    },
                    orientation="h",
                    hover_data={id_col_name: True, "Nilai SHAP": ":.4f",
                                "Kata Kunci (Token Teks)": True, "Kategori Dampak": False}
                )
                fig_beeswarm.update_traces(jitter=0.5, marker=dict(size=8, opacity=0.85))
                fig_beeswarm.update_layout(
                    title="Beeswarm Plot",
                    margin=dict(l=20, r=20, t=40, b=20),
                    height=380,
                    xaxis_title="Nilai SHAP (Dampak Terhadap Skor Prediksi)",
                    yaxis_title="Fitur Kata Kunci Tekstual",
                    legend_title_text="",
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                    yaxis=dict(categoryorder="array", categoryarray=order_list)
                )

    return fig_shap_hist, fig_beeswarm, has_features


def render_tab_shap_visual(app_model=None, scanner=None):
    """
    Menampilkan Visualisasi SHAP dari riwayat pemindaian (dibaca melalui API backend)
    berdasarkan sesi riwayat yang dipilih pengguna.

    scanner: "SAST", "DAST", atau "HYBRID" untuk menyematkan bagian ini di tab pemindai tersebut
    (cakupan tetap, tanpa filter tipe scanner). None menampilkan semua pemindai dengan filter.
    """
    if not app_model:
        app_model = get_active_model()

    scope = SCANNER_SCOPES.get(str(scanner).upper()) if scanner else None
    key_prefix = f"shap_{str(scanner).lower()}" if scope else "shap"

    if scope:
        st.markdown("---")
        st.subheader("Penjelasan Skor (SHAP)")
    else:
        st.subheader("Visualisasi Transparansi Kontribusi Fitur SHAP")
    st.write(
        "Modul visualisasi analitis ini menyajikan diagram signifikansi fitur (*Feature Importance Bar Chart*) "
        "dan diagram dispersi atribusi (*Beeswarm Plot*) guna menginterpretasikan distribusi kontribusi nilai SHAP "
        "secara langsung dari data history empiris pengujian yang tersimpan dalam database pada session terpilih."
    )

    try:
        df_history = load_all_history((scope[0],) if scope else HISTORY_SCANNERS)
    except ApiError as e:
        st.error(f"Gagal membaca database history: {e}")
        return

    if df_history.empty:
        st.info("Belum ada test history yang tersimpan di database.")
        return

    df_history['cwe_id'] = df_history['cwe_id'].fillna("N/A")
    if 'predicted_score' not in df_history.columns and 'predicted_cvss4_score' in df_history.columns:
        df_history['predicted_score'] = df_history['predicted_cvss4_score']

    # Saring tipe pemindai, termasuk dukungan eksplisit untuk Hybrid (HAST)
    scanner_types = [
        "Semua Scanner",
        "SonarQube (SAST)",
        "OWASP ZAP (DAST)",
        "Pengujian Korelasi Hybrid (HAST)"
    ]
    if scope:
        # Tersemat di tab pemindai: riwayat sudah dibatasi pada pemindai ini, jadi tanpa filter tipe scanner.
        selected_scanner = scope[1]
    else:
        col_sc, col_batch = st.columns([1, 1])
        with col_sc:
            selected_scanner = st.selectbox(
                "Filter Tipe Scanner:",
                scanner_types,
                index=0,
                key="shap_filter_scanner"
            )

    if scope:
        df_scoped = df_history
    elif selected_scanner == "Semua Scanner":
        df_scoped = df_history
    elif "Hybrid" in selected_scanner or "HAST" in selected_scanner:
        # Baris "Temuan Pemindai Tunggal" berbagi batch HAST-* tetapi bukan pasangan hybrid.
        df_scoped = df_history[
            df_history['scanner_type'].str.contains("Hybrid", case=False, na=False) |
            (df_history['batch_id'].str.startswith("HAST-") &
             ~df_history['scanner_type'].str.contains("Tunggal", case=False, na=False))
        ]
    elif "SAST" in selected_scanner or "SonarQube" in selected_scanner:
        df_scoped = df_history[
            (df_history['scanner_type'].str.contains("SAST|SonarQube", case=False, na=False) | df_history['batch_id'].str.startswith("SAST-")) &
            ~df_history['scanner_type'].str.contains("Hybrid", case=False, na=False)
        ]
    elif "DAST" in selected_scanner or "OWASP ZAP" in selected_scanner:
        df_scoped = df_history[
            (df_history['scanner_type'].str.contains("DAST|OWASP", case=False, na=False) | df_history['batch_id'].str.startswith("DAST-")) &
            ~df_history['scanner_type'].str.contains("Hybrid", case=False, na=False)
        ]
    else:
        df_scoped = df_history[df_history['scanner_type'] == selected_scanner]

    unique_batches = []
    for b in df_scoped['batch_id'].tolist():
        if b not in unique_batches:
            unique_batches.append(b)

    if not unique_batches:
        st.info(f"Belum ada test history session untuk kategori {selected_scanner}.")
        return

    def get_batch_label_shap(b_id):
        m = df_history[df_history['batch_id'] == b_id]
        date_str = ""
        sc_tag = ""
        if not m.empty:
            sc_raw = str(m['scanner_type'].iloc[0]) if ('scanner_type' in m.columns and pd.notna(m['scanner_type'].iloc[0])) else ""
            if "Hybrid" in sc_raw or str(b_id).startswith("HAST-"):
                sc_tag = "[Hybrid (HAST)] "
            elif "SAST" in sc_raw or "SonarQube" in sc_raw or str(b_id).startswith("SAST-"):
                sc_tag = "[SonarQube (SAST)] "
            elif "DAST" in sc_raw or "OWASP ZAP" in sc_raw or str(b_id).startswith("DAST-"):
                sc_tag = "[OWASP ZAP (DAST)] "
            elif sc_raw:
                sc_tag = f"[{sc_raw}] "

            if 'timestamp' in m.columns and pd.notna(m['timestamp'].iloc[0]):
                try:
                    dt = pd.to_datetime(str(m['timestamp'].iloc[0]))
                    date_str = dt.strftime("%Y/%m/%d %H:%M")
                except Exception:
                    pass
        if not date_str and "-" in str(b_id):
            try:
                unix_ts = int(str(b_id).split("-")[-1])
                dt = datetime.datetime.fromtimestamp(unix_ts)
                date_str = dt.strftime("%Y/%m/%d %H:%M")
            except Exception:
                pass
        if date_str:
            return f"{sc_tag}{b_id} ({date_str})"
        return f"{sc_tag}{b_id}"

    if scope:
        # Tersemat di tab pemindai: sesi mengikuti pilihan di bagian "Riwayat Analisis" pada tab yang sama
        # (dirender lebih dulu dalam rerun yang sama), jadi tidak ada pemilih sesi terpisah.
        selected_batch = st.session_state.get(history_selectbox_key(scope[0]))
        if selected_batch not in unique_batches:
            selected_batch = unique_batches[0]
        st.caption(f"Session mengikuti pilihan pada Analysis History {scope[0]}: **{get_batch_label_shap(selected_batch)}**")
    else:
        with col_batch:
            selected_batch = st.selectbox(
                "Pilih Test History Session:",
                unique_batches,
                index=0,
                key=f"{key_prefix}_selected_batch",
                format_func=get_batch_label_shap
            )

    df_batch = df_scoped[df_scoped['batch_id'] == selected_batch].copy()
    # Sembunyikan temuan berkategori NONE
    df_active_batch = df_batch[df_batch['predicted_severity'].str.upper() != 'NONE'].copy()
    if df_active_batch.empty and not df_batch.empty:
        df_active_batch = df_batch.copy()

    df_selected = df_active_batch

    if df_selected.empty:
        st.info("Tidak ada data celah kerentanan pada test session yang dipilih.")
        return

    # Tentukan tipe pemindai untuk sesi ini
    scanner_type = df_selected['scanner_type'].iloc[0] if 'scanner_type' in df_selected.columns else "SonarQube (SAST)"
    is_hybrid = ("Hybrid" in str(scanner_type) or str(selected_batch).startswith("HAST-"))
    is_sast = ("SAST" in str(scanner_type) or "SonarQube" in str(scanner_type)) and not is_hybrid
    is_dast = ("DAST" in str(scanner_type) or "OWASP ZAP" in str(scanner_type)) and not is_hybrid
    id_col_name = "Pair ID" if is_hybrid else "Key ID"

    # Ekstrak nilai SHAP dari kolom deskripsi
    history_shap_report = []

    for _, r_hist in df_selected.iterrows():
        raw_desc_text = str(r_hist.get('description', ''))
        raw_comp_string = str(r_hist.get('component', '')).strip()

        if is_hybrid:
            if 'sast_description' in r_hist and pd.notna(r_hist['sast_description']) and str(r_hist['sast_description']).strip() not in ('', 'None', 'nan'):
                sast_issue_desc = str(r_hist['sast_description']).strip()
            else:
                sast_desc_match = re.search(r'\[SAST\]:\s*(.*?)(?=(?:\r?\n|\s*)\[DAST\]:|$)', raw_desc_text, re.DOTALL)
                sast_issue_desc = sast_desc_match.group(1).strip() if sast_desc_match else "N/A"

            sast_issue_desc = re.sub(
                r'(?:\r?\n|\s+)\[(?:BASE_SCORE|SHAP_PRED|SHAP_BASE|SHAP_TOT_POS|SHAP_TOT_NEG|ABSENT_VOCAB|XAI_DESC|SHAP_POS|SHAP_NEG)\].*$',
                '', sast_issue_desc, flags=re.DOTALL
            ).strip()
            if sast_issue_desc != "N/A":
                sast_issue_desc = re.sub(r'^(?:PAIR-)?[A-Fa-f0-9]{8}\s*-\s*', '', sast_issue_desc).strip()

            if 'dast_description' in r_hist and pd.notna(r_hist['dast_description']) and str(r_hist['dast_description']).strip() not in ('', 'None', 'nan'):
                dast_issue_desc = str(r_hist['dast_description']).strip()
            else:
                dast_desc_match = re.search(
                    r'\[DAST\]:\s*(.*?)(?=(?:\r?\n|\s*)\[BASE_SCORE\]:|(?:\r?\n|\s*)\[XAI_DESC\]:|(?:\r?\n|\s*)\[MITIGATION\]:|$)',
                    raw_desc_text, re.DOTALL)
                dast_issue_desc = dast_desc_match.group(1).strip() if dast_desc_match else "N/A"

            mitigation_clean_pattern = r'\n\[MITIGATION\]:\s*(.*)'
            dast_issue_desc_clean = re.sub(mitigation_clean_pattern, '', dast_issue_desc).strip()
            dast_issue_desc_clean = re.sub(
                r'(?:\r?\n|\s+)\[(?:BASE_SCORE|SHAP_PRED|SHAP_BASE|SHAP_TOT_POS|SHAP_TOT_NEG|ABSENT_VOCAB|XAI_DESC|SHAP_POS|SHAP_NEG)\].*$',
                '', dast_issue_desc_clean, flags=re.DOTALL
            ).strip()
            dast_issue_desc_clean = re.sub(r'<[^>]*>', '', dast_issue_desc_clean).strip()

            shap_sast_input = sast_issue_desc if sast_issue_desc != "N/A" else ""
            shap_dast_input = dast_issue_desc_clean if dast_issue_desc_clean != "N/A" else ""
        elif is_sast:
            if 'sast_description' in r_hist and pd.notna(r_hist['sast_description']) and str(r_hist['sast_description']).strip() not in ('', 'None', 'nan'):
                sast_issue_desc = str(r_hist['sast_description']).strip()
            else:
                clean_desc = re.sub(r'\n\[MITIGATION\]:.*$', '', raw_desc_text, flags=re.DOTALL).strip()
                clean_desc = re.sub(r'(?:\r?\n|\s+)\[(?:BASE_SCORE|SHAP_PRED|SHAP_BASE|SHAP_TOT_POS|SHAP_TOT_NEG|XAI_DESC|SHAP_POS|SHAP_NEG)\].*$', '', clean_desc, flags=re.DOTALL).strip()
                clean_desc = re.sub(r'^(?:PAIR-)?[A-Fa-f0-9]{8}\s*-\s*', '', clean_desc).strip()
                sast_issue_desc = re.sub(r'<[^>]*>', '', clean_desc).strip()
            dast_issue_desc_clean = "N/A"
            shap_sast_input = sast_issue_desc
            shap_dast_input = ""
        else:  # is_dast
            if 'dast_description' in r_hist and pd.notna(r_hist['dast_description']) and str(r_hist['dast_description']).strip() not in ('', 'None', 'nan'):
                dast_issue_desc_clean = str(r_hist['dast_description']).strip()
            else:
                clean_desc = re.sub(r'\n\[MITIGATION\]:.*$', '', raw_desc_text, flags=re.DOTALL).strip()
                clean_desc = re.sub(r'(?:\r?\n|\s+)\[(?:BASE_SCORE|SHAP_PRED|SHAP_BASE|SHAP_TOT_POS|SHAP_TOT_NEG|XAI_DESC|SHAP_POS|SHAP_NEG)\].*$', '', clean_desc, flags=re.DOTALL).strip()
                dast_issue_desc_clean = re.sub(r'<[^>]*>', '', clean_desc).strip()
            sast_issue_desc = "N/A"
            shap_sast_input = ""
            shap_dast_input = dast_issue_desc_clean

        # Ambil nilai metrik SHAP langsung dari kolom basis data khusus bila tersedia
        if 'shap_pos' in r_hist and pd.notna(r_hist['shap_pos']) and str(r_hist['shap_pos']).strip() not in ('', 'None'):
            shap_pos_val = str(r_hist['shap_pos']).strip()
        elif 'shap_positive' in r_hist and pd.notna(r_hist['shap_positive']) and str(r_hist['shap_positive']).strip() not in ('', 'None'):
            shap_pos_val = str(r_hist['shap_positive']).strip()
        else:
            shap_pos_match = re.search(r'\[SHAP_POS\]:\s*(.*?)(?=(?:\r?\n|\s*)\[SHAP_NEG\]:|$)', raw_desc_text, re.DOTALL)
            shap_pos_val = shap_pos_match.group(1).strip() if shap_pos_match else "N/A"

        if 'shap_neg' in r_hist and pd.notna(r_hist['shap_neg']) and str(r_hist['shap_neg']).strip() not in ('', 'None'):
            shap_neg_val = str(r_hist['shap_neg']).strip()
        elif 'shap_negative' in r_hist and pd.notna(r_hist['shap_negative']) and str(r_hist['shap_negative']).strip() not in ('', 'None'):
            shap_neg_val = str(r_hist['shap_negative']).strip()
        else:
            shap_neg_match = re.search(r'\[SHAP_NEG\]:\s*(.*?)(?=$)', raw_desc_text, re.DOTALL)
            shap_neg_val = shap_neg_match.group(1).strip() if shap_neg_match else "N/A"

        if 'shap_base_value' in r_hist and pd.notna(r_hist['shap_base_value']) and float(r_hist['shap_base_value']) != 0.0:
            shap_base_val = f"{float(r_hist['shap_base_value']):.2f}"
        else:
            shap_base_match = re.search(r'\[SHAP_BASE\]:\s*([\-\d\.]+)', raw_desc_text)
            shap_base_val = f"{float(shap_base_match.group(1)):.2f}" if shap_base_match else "N/A"

        if 'shap_total_pos' in r_hist and pd.notna(r_hist['shap_total_pos']) and str(r_hist['shap_total_pos']).strip() not in ('', 'None'):
            shap_tot_pos_val = f"{float(r_hist['shap_total_pos']):.2f}"
        else:
            shap_tot_pos_match = re.search(r'\[SHAP_TOT_POS\]:\s*([\-\d\.]+)', raw_desc_text)
            shap_tot_pos_val = f"{float(shap_tot_pos_match.group(1)):.2f}" if shap_tot_pos_match else "N/A"

        if 'shap_total_neg' in r_hist and pd.notna(r_hist['shap_total_neg']) and str(r_hist['shap_total_neg']).strip() not in ('', 'None'):
            shap_tot_neg_val = f"{float(r_hist['shap_total_neg']):.2f}"
        else:
            shap_tot_neg_match = re.search(r'\[SHAP_TOT_NEG\]:\s*([\-\d\.]+)', raw_desc_text)
            shap_tot_neg_val = f"{float(shap_tot_neg_match.group(1)):.2f}" if shap_tot_neg_match else "N/A"

        if 'shap_predicted_score' in r_hist and pd.notna(r_hist['shap_predicted_score']) and float(r_hist['shap_predicted_score']) != 0.0:
            shap_pred_val = f"{float(r_hist['shap_predicted_score']):.2f}"
        else:
            shap_pred_match = re.search(r'\[SHAP_PRED\]:\s*([\-\d\.]+)', raw_desc_text)
            shap_pred_val = f"{float(shap_pred_match.group(1)):.2f}" if shap_pred_match else "N/A"

        if 'base_score' in r_hist and pd.notna(r_hist['base_score']) and float(r_hist['base_score']) != 0.0:
            base_score_val = f"{float(r_hist['base_score']):.2f}"
        else:
            base_score_match = re.search(r'\[BASE_SCORE\]:\s*([\d\.]+)', raw_desc_text)
            if base_score_match:
                base_score_val = f"{float(base_score_match.group(1)):.2f}"
            else:
                base_score_val = f"{float(r_hist['predicted_score']):.2f}"

        # Bila SHAP tidak ada atau bernilai N/A/0.00 akibat kegagalan sebelumnya, hitung saat dibutuhkan dan perbarui basis data
        needs_calc = (
            shap_pos_val == "N/A"
            or shap_base_val in ("N/A", "0.00")
            or "[SHAP_POS]: N/A" in raw_desc_text
        ) and bool(shap_sast_input or shap_dast_input)

        if needs_calc:
            # v2: baris tersimpan dihitung SEKALIGUS disimpan oleh backend; baris lain memakai endpoint tanpa status.
            shap_calc = {}
            try:
                if 'id' in r_hist and pd.notna(r_hist['id']):
                    shap_calc = compute_history_shap([{
                        "id": int(r_hist['id']),
                        "sast_description": shap_sast_input or "",
                        "dast_description": shap_dast_input or "",
                    }])[0]
                else:
                    shap_calc = hit_shap_api(shap_sast_input, shap_dast_input)
            except ApiError:
                shap_calc = {}

            if shap_calc:
                shap_pos_val = shap_calc.get("shap_positive", "N/A")
                shap_neg_val = shap_calc.get("shap_negative", "N/A")
                if "shap_base_value" in shap_calc:
                    shap_base_val = f"{float(shap_calc['shap_base_value']):.2f}"
                if "shap_total_pos" in shap_calc:
                    shap_tot_pos_val = f"{float(shap_calc['shap_total_pos']):.2f}"
                if "shap_total_neg" in shap_calc:
                    shap_tot_neg_val = f"{float(shap_calc['shap_total_neg']):.2f}"
                if "shap_predicted_score" in shap_calc:
                    shap_pred_val = f"{float(shap_calc['shap_predicted_score']):.2f}"


        pos_nums = [float(x) for x in re.findall(r'\(\+?([\d\.]+)\)', str(shap_pos_val))]
        neg_nums = [float(x) for x in re.findall(r'\(([\-\d\.]+)\)', str(shap_neg_val))]

        if shap_tot_pos_val in ("N/A", "", None):
            if pos_nums:
                shap_tot_pos_val = f"{sum(pos_nums):.2f}"
            else:
                shap_tot_pos_val = "0.00"

        if shap_tot_neg_val in ("N/A", "", None):
            if neg_nums:
                shap_tot_neg_val = f"{sum(neg_nums):.2f}"
            else:
                shap_tot_neg_val = "0.00"

        try:
            target_score = float(base_score_val)
        except Exception:
            try:
                target_score = float(r_hist['predicted_score'])
            except Exception:
                target_score = float(shap_pred_val) if shap_pred_val != "N/A" else 0.0

        shap_pred_val = f"{target_score:.2f}"

        if 'absent_vocab_bias' in r_hist and pd.notna(r_hist['absent_vocab_bias']) and str(r_hist['absent_vocab_bias']).strip() not in ('', 'None'):
            absent_vocab_val = f"{float(r_hist['absent_vocab_bias']):.2f}"
        else:
            absent_vocab_match = re.search(r'\[ABSENT_VOCAB\]:\s*([\-\d\.]+)', raw_desc_text)
            if absent_vocab_match:
                absent_vocab_val = f"{float(absent_vocab_match.group(1)):.2f}"
            else:
                try:
                    absent_vocab_val = f"{target_score - (float(shap_base_val) + float(shap_tot_pos_val) + float(shap_tot_neg_val)):.2f}"
                except Exception:
                    absent_vocab_val = "0.00"

        shap_row = {
            id_col_name: r_hist.get('key_id', 'N/A'),
            "Final Severity" if is_hybrid else "Predicted Severity": r_hist.get('predicted_severity', 'NONE'),
            "Hybrid Score" if is_hybrid else "Predicted Score": f"{float(r_hist['predicted_score']):.2f}",
            "CWE ID": r_hist.get('cwe_id', 'N/A'),
            "Impacted Component": raw_comp_string,
        }
        if is_hybrid:
            shap_row["Vulnerability Description (SonarQube SAST)"] = shap_sast_input if shap_sast_input else "N/A"
            shap_row["Vulnerability Description (OWASP ZAP DAST)"] = shap_dast_input if shap_dast_input else "N/A"
        elif is_sast:
            shap_row["Vulnerability Message (SonarQube SAST)"] = shap_sast_input if shap_sast_input else "N/A"
        else:
            shap_row["Vulnerability Description (OWASP ZAP DAST)"] = shap_dast_input if shap_dast_input else "N/A"

        shap_row.update({
            "SHAP Base Value": shap_base_val,
            "Total SHAP Positive": shap_tot_pos_val,
            "Total SHAP Negative": shap_tot_neg_val,
            "Absent Vocabulary Bias": absent_vocab_val,
            "SHAP Predicted Score": shap_pred_val,
            "Dominant Vulnerability Aggravating Factors (SHAP Positive)": shap_pos_val,
            "Dominant Vulnerability Reducing Factors (SHAP Negative)": shap_neg_val
        })
        history_shap_report.append(shap_row)

    # Bangun Feature Importance Bar Chart dan Beeswarm Plot
    fig_shap_hist, fig_beeswarm, has_features = build_shap_figures_from_records(history_shap_report, id_col_name=id_col_name)

    st.markdown("---")
    st.markdown(f"#### Hasil Analisis Transparansi SHAP: {selected_batch}")

    if has_features and fig_shap_hist:
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.plotly_chart(fig_shap_hist, width="stretch")
        with col_c2:
            if fig_beeswarm:
                st.plotly_chart(fig_beeswarm, width="stretch")
            else:
                st.info("Data Beeswarm Plot belum tersedia untuk session ini.")
        st.caption(
            "*Glosarium metrik kalkulasi SHAP, definisi variabel, serta formulasi matematis lengkap (SHAP Base Value, Total SHAP Positive, Total SHAP Negative, Absent Vocabulary Bias, dan SHAP Predicted Score) tersedia secara terperinci pada tab **Analisis Riset**.*"
        )
    else:
        st.info("Data kontribusi token fitur SHAP belum tersedia atau tidak teridentifikasi pada test session ini.")

    # Tabel rincian data SHAP
    df_shap_table = pd.DataFrame(history_shap_report)
    if not df_shap_table.empty:
        st.markdown("##### Tabel Dekomposisi Kuantitatif Nilai SHAP")
        st.dataframe(df_shap_table, width="stretch", hide_index=True)

        csv_data_shap = df_shap_table.to_csv(index=False)
        dl_shap_filename = f"Laporan_Analisis_SHAP_{selected_batch}.csv"
        st.download_button(
            label="Export Laporan Analisis SHAP (.csv)",
            data=csv_data_shap,
            file_name=dl_shap_filename,
            mime="text/csv",
            use_container_width=True,
            key=f"btn_dl_{key_prefix}_tab_{selected_batch}"
        )
