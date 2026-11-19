import re
import datetime
import threading
import pandas as pd
import numpy as np
import plotly.express as px
import streamlit as st

from frontend.utils.api_client import ApiError, compute_history_shap, hit_shap_api, list_history
from frontend.utils.formatters import prefix_scanner
from frontend.components.dialogs import confirm_delete_batch_dialog, confirm_clear_all_dialog

# Pengelolaan cache dan status pekerja latar belakang untuk SHAP
_SHAP_CACHE = {}
_SHAP_WORKERS = set()
_SHAP_LOCK = threading.Lock()


def clear_shap_cache(batch_id=None):
    """Mengosongkan cache SHAP saat suatu sesi dihapus."""
    with _SHAP_LOCK:
        if batch_id:
            keys_to_del = [k for k in _SHAP_CACHE if k.startswith(f"{batch_id}_")]
            for k in keys_to_del:
                _SHAP_CACHE.pop(k, None)
        else:
            _SHAP_CACHE.clear()


def _worker_compute_shap(cache_key, rows_data, is_hybrid, is_sast, is_dast, id_col_name):
    """Fungsi pekerja latar belakang untuk perhitungan SHAP dan pembuatan grafik."""
    try:
        history_shap_report = []

        items_parsed = []
        indices_to_compute = []
        pairs_to_compute = []

        for idx, r_hist in enumerate(rows_data):
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

            needs_calc = (
                shap_pos_val == "N/A"
                or shap_base_val in ("N/A", "0.00")
                or "[SHAP_POS]: N/A" in raw_desc_text
            ) and bool(shap_sast_input or shap_dast_input)
            if needs_calc:
                indices_to_compute.append(idx)
                pairs_to_compute.append((shap_sast_input, shap_dast_input))

            items_parsed.append({
                "r_hist": r_hist,
                "raw_desc_text": raw_desc_text,
                "raw_comp_string": raw_comp_string,
                "shap_pos_val": shap_pos_val,
                "shap_neg_val": shap_neg_val,
                "shap_base_val": shap_base_val,
                "shap_tot_pos_val": shap_tot_pos_val,
                "shap_tot_neg_val": shap_tot_neg_val,
                "shap_pred_val": shap_pred_val,
                "base_score_val": base_score_val,
                "shap_sast_input": shap_sast_input,
                "shap_dast_input": shap_dast_input,
                "needs_calc": needs_calc
            })

        if pairs_to_compute:
            # v2: backend menghitung SEKALIGUS menyimpan nilai SHAP yang belum ada untuk baris tersimpan
            # (POST /api/v1/history/shap). Baris tanpa id basis data memakai endpoint tanpa status.
            calc_results = [{}] * len(pairs_to_compute)
            stored = [(pos, items_parsed[i]["r_hist"]) for pos, i in enumerate(indices_to_compute)
                      if pd.notna(items_parsed[i]["r_hist"].get("id", None))]
            try:
                if stored:
                    res_stored = compute_history_shap([
                        {"id": int(r["id"]), "sast_description": pairs_to_compute[pos][0] or "",
                         "dast_description": pairs_to_compute[pos][1] or ""}
                        for pos, r in stored
                    ])
                    for (pos, _r), res in zip(stored, res_stored):
                        calc_results[pos] = res
                stored_pos = {pos for pos, _ in stored}
                for pos, (s_in, d_in) in enumerate(pairs_to_compute):
                    if pos not in stored_pos:
                        calc_results[pos] = hit_shap_api(s_in, d_in)
            except ApiError:
                pass

            for target_idx, shap_calc in zip(indices_to_compute, calc_results):
                it = items_parsed[target_idx]
                if shap_calc:
                    it["shap_pos_val"] = shap_calc.get("shap_positive", "N/A")
                    it["shap_neg_val"] = shap_calc.get("shap_negative", "N/A")
                    if "shap_base_value" in shap_calc:
                        it["shap_base_val"] = f"{float(shap_calc['shap_base_value']):.2f}"
                    if "shap_total_pos" in shap_calc:
                        it["shap_tot_pos_val"] = f"{float(shap_calc['shap_total_pos']):.2f}"
                    if "shap_total_neg" in shap_calc:
                        it["shap_tot_neg_val"] = f"{float(shap_calc['shap_total_neg']):.2f}"
                    if "shap_predicted_score" in shap_calc:
                        it["shap_pred_val"] = f"{float(shap_calc['shap_predicted_score']):.2f}"

        for it in items_parsed:
            r_hist = it["r_hist"]
            shap_pos_val = it["shap_pos_val"]
            shap_neg_val = it["shap_neg_val"]
            shap_base_val = it["shap_base_val"]
            shap_tot_pos_val = it["shap_tot_pos_val"]
            shap_tot_neg_val = it["shap_tot_neg_val"]
            shap_pred_val = it["shap_pred_val"]
            base_score_val = it["base_score_val"]

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

            if 'absent_vocab_bias' in r_hist and pd.notna(r_hist['absent_vocab_bias']) and str(r_hist['absent_vocab_bias']).strip() not in ('', 'None'):
                absent_vocab_val = f"{float(r_hist['absent_vocab_bias']):.2f}"
            else:
                absent_vocab_match = re.search(r'\[ABSENT_VOCAB\]:\s*([\-\d\.]+)', it["raw_desc_text"])
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
                "Impacted Component": it["raw_comp_string"],
            }
            if is_hybrid:
                shap_row["Vulnerability Description (SonarQube SAST)"] = it.get("shap_sast_input", "N/A")
                shap_row["Vulnerability Description (OWASP ZAP DAST)"] = it.get("shap_dast_input", "N/A")
            elif is_sast:
                shap_row["Vulnerability Message (SonarQube SAST)"] = it.get("shap_sast_input", "N/A")
            else:
                shap_row["Vulnerability Description (OWASP ZAP DAST)"] = it.get("shap_dast_input", "N/A")

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

        df_history_shap_out = pd.DataFrame(history_shap_report)
        csv_data_hist_shap = df_history_shap_out.to_csv(index=False)

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

        with _SHAP_LOCK:
            _SHAP_CACHE[cache_key] = {
                "status": "ready",
                "fig_shap_hist": fig_shap_hist,
                "fig_beeswarm": fig_beeswarm,
                "csv_data_hist_shap": csv_data_hist_shap,
                "has_features": has_features
            }
    except Exception as e:
        with _SHAP_LOCK:
            _SHAP_CACHE[cache_key] = {
                "status": "error",
                "error": str(e)
            }
    finally:
        with _SHAP_LOCK:
            _SHAP_WORKERS.discard(cache_key)


def _render_shap_charts(data):
    """Menampilkan Feature Importance dan Beeswarm Plot secara statis setelah perhitungan selesai."""
    st.markdown("---")
    st.markdown("##### Transparansi Kontribusi Fitur Menggunakan SHAP (Feature Importance & Beeswarm Plot)")
    if data.get("has_features") and data.get("fig_shap_hist"):
        col_chart1, col_chart2 = st.columns(2)
        with col_chart1:
            st.plotly_chart(data["fig_shap_hist"], width="stretch")
        with col_chart2:
            if data.get("fig_beeswarm"):
                st.plotly_chart(data["fig_beeswarm"], width="stretch")
            else:
                st.info("Data Beeswarm Plot belum tersedia untuk session ini.")
        st.caption(
            "*Legenda metrik kalkulasi SHAP, definisi variabel, dan formulasi matematis lengkap (Base Score, SHAP Base Value, Total Positive, Total Negative, Absent Vocabulary Bias, & Predicted Score) tersedia pada tab **Analisis Riset**.*"
        )
    else:
        st.info("Data kontribusi fitur SHAP belum tersedia untuk session ini.")


@st.cache_data(ttl=5)
def load_cached_scan_history(scanner_type: str) -> pd.DataFrame:
    """Mengambil riwayat pemindaian untuk satu tipe pemindai (melalui API backend) dengan cache TTL singkat."""
    return list_history(scanner_type)


def history_selectbox_key(scanner_type: str) -> str:
    """Key st.selectbox sesi riwayat; dibaca juga oleh bagian SHAP agar mengikuti sesi yang sama."""
    return f"filter_{scanner_type.replace(' ', '_').replace('(', '').replace(')', '')}"


def render_embedded_history(scanner_type, app_model="Random Forest"):
    """Menampilkan komponen antarmuka riwayat analisis."""
    st.markdown("---")
    st.subheader(f"Analysis History {scanner_type}")
    active_model = app_model if app_model != "Unknown" else "Random Forest"
    try:
        df_history = load_cached_scan_history(scanner_type).copy()

        if df_history.empty:
            st.info(f"Belum ada test history untuk {scanner_type}.")
        else:
            df_history['cwe_id'] = df_history['cwe_id'].fillna("N/A")

            if 'predicted_score' not in df_history.columns and 'predicted_cvss4_score' in df_history.columns:
                df_history['predicted_score'] = df_history['predicted_cvss4_score']

            unique_batches = []
            for b in df_history['batch_id'].tolist():
                if b not in unique_batches:
                    unique_batches.append(b)

            def get_batch_label(b_id):
                m = df_history[df_history['batch_id'] == b_id]
                date_str = ""
                if not m.empty and 'timestamp' in m.columns and pd.notna(m['timestamp'].iloc[0]):
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
                    return f"{b_id} ({date_str})"
                return str(b_id)

            key_selectbox = history_selectbox_key(scanner_type)
            col_batch, col_sev = st.columns(2)
            with col_batch:
                selected_batch = st.selectbox(
                    "Pilih Test History Session:",
                    unique_batches,
                    index=0,
                    key=key_selectbox,
                    format_func=get_batch_label
                )
            with col_sev:
                severity_filter = st.multiselect(
                    "Pilih Severity Level:",
                    options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    default=[],
                    placeholder="Semua Severity Level",
                    key=f"sev_hist_{prefix_scanner(scanner_type)}"
                )

            df_batch = df_history[df_history['batch_id'] == selected_batch]
            # Sembunyikan temuan berkeparahan NONE agar fokus pada kerentanan aktif
            df_active_batch = df_batch[df_batch['predicted_severity'].str.upper() != 'NONE'].copy()
            if df_active_batch.empty and not df_batch.empty:
                df_active_batch = df_batch.copy()

            if severity_filter:
                df_filtered = df_active_batch[df_active_batch['predicted_severity'].str.upper().isin(severity_filter)]
            else:
                df_filtered = df_active_batch

            is_hybrid = (scanner_type == "Pengujian Korelasi Hybrid")

            st.markdown("#### Ringkasan Eksekutif Test Session History")
            m1, m2, m3, m4 = st.columns(4)

            if not df_filtered.empty:
                median_score = float(df_filtered['predicted_score'].median())
                max_score = float(df_filtered['predicted_score'].max())
                critical_high_count = len(
                    df_filtered[df_filtered['predicted_severity'].str.upper().isin(['CRITICAL', 'HIGH'])])
            else:
                median_score = 0.0
                max_score = 0.0
                critical_high_count = 0
            total_cases = len(df_filtered)

            # Ekstrak dan hitung informasi CWE-ID unik/beririsan untuk tooltip
            unique_cwes = []
            if not df_filtered.empty and 'cwe_id' in df_filtered.columns:
                for raw_cwe in df_filtered['cwe_id'].dropna():
                    raw_str = str(raw_cwe).strip()
                    if not raw_str or raw_str.upper() in ['N/A', 'NONE', 'UNKNOWN', 'NULL', '0', '-1']:
                        continue
                    cwes_found = re.findall(r'CWE-\d+', raw_str, re.IGNORECASE)
                    if cwes_found:
                        for c in cwes_found:
                            if c.upper() not in unique_cwes:
                                unique_cwes.append(c.upper())
                    else:
                        if raw_str.upper() not in [c.upper() for c in unique_cwes]:
                            unique_cwes.append(raw_str)

                def _sort_cwe_key(cwe_val):
                    match = re.search(r'\d+', cwe_val)
                    return (0, int(match.group(0))) if match else (1, cwe_val)

                unique_cwes = sorted(unique_cwes, key=_sort_cwe_key)

            if unique_cwes:
                cwe_str = ", ".join(unique_cwes)
                if is_hybrid:
                    cwe_tooltip = f"Mencakup {len(unique_cwes)} CWE-ID yang bersilangan: {cwe_str}"
                else:
                    cwe_tooltip = f"Mencakup {len(unique_cwes)} CWE-ID: {cwe_str}"
            else:
                cwe_tooltip = "Jumlah total temuan celah kerentanan"

            m1.metric(
                label="Skor Median (CVSS 4.0)",
                value=f"{median_score:.2f}",
                help="Nilai tengah (median) estimasi skor CVSS v4.0 dari seluruh temuan kerentanan. Menggambarkan severity level tipikal sistem yang lebih stabil dan tidak terdistorsi oleh temuan ekstrem (pencilan)."
            )
            m2.metric(
                label="Skor Kerentanan Tertinggi",
                value=f"{max_score:.2f}",
                help="Skor estimasi CVSS v4.0 tertinggi yang terdeteksi pada test session ini. Menandakan celah keamanan paling kritis yang berpotensi menimbulkan dampak risiko terbesar dan memerlukan prioritas penanganan utama."
            )
            m3.metric(label="Total Temuan Celah", value=f"{total_cases}", help=cwe_tooltip)
            m4.metric(label="Kerentanan Kritis & Tinggi", value=f"{critical_high_count}",
                      help="Jumlah celah kerentanan kategori Critical (9.0-10.0) & High (7.0-8.9)")

            st.markdown("<div style='padding-top: 10px;'></div>", unsafe_allow_html=True)

            df_filtered_sorted = df_filtered.sort_values(
                by='predicted_score', ascending=False).reset_index(drop=True)
            df_filtered_en = df_filtered_sorted.copy()
            df_filtered_en.insert(0, 'No', df_filtered_en.index + 1)

            df_display = pd.DataFrame()
            df_display['No'] = df_filtered_en['No']
            df_display['Batch ID'] = df_filtered_en['batch_id']
            df_display['Timestamp'] = df_filtered_en['timestamp']
            df_display['Key ID'] = df_filtered_en.get('key_id', df_filtered_en.get('Key ID', 'N/A'))
            df_display['CWE ID'] = df_filtered_en.get('cwe_id', df_filtered_en.get('CWE ID', 'N/A'))
            df_display['Component'] = df_filtered_en.get('component', df_filtered_en.get('Component', 'N/A'))
            df_display['Predicted Score'] = df_filtered_en['predicted_score']
            df_display['Predicted Severity'] = df_filtered_en.get(
                'predicted_severity', df_filtered_en.get('Predicted Severity', 'NONE'))

            if 'Predicted Score' in df_display.columns:
                df_display['Predicted Score'] = df_display['Predicted Score'].map(
                    lambda x: f"{float(x):.2f}" if pd.notna(x) else "N/A")

            st.dataframe(df_display, width="stretch", hide_index=True)

            if not df_filtered.empty:
                is_hybrid = (scanner_type == "Pengujian Korelasi Hybrid")
                is_sast = ("SAST" in scanner_type or "SonarQube" in scanner_type)
                is_dast = ("DAST" in scanner_type or "OWASP ZAP" in scanner_type)
                id_col_name = "Pair ID" if is_hybrid else "Key ID"
                sev_col_name = "Final Severity" if is_hybrid else "Predicted Severity"
                score_col_name = "Hybrid Score" if is_hybrid else "Predicted Score"

                history_main_report = []
                for _, r_hist in df_filtered_sorted.iterrows():
                    raw_desc_text = str(r_hist.get('description', ''))
                    raw_comp_string = str(r_hist.get('component', '')).strip()

                    if is_hybrid:
                        sast_desc_match = re.search(r'\[SAST\]:\s*(.*?)(?=\n\[DAST\]:|$)', raw_desc_text, re.DOTALL)
                        dast_desc_match = re.search(
                            r'\[DAST\]:\s*(.*?)(?=\n\[BASE_SCORE\]:|\n\[XAI_DESC\]:|\n\[MITIGATION\]:|$)', raw_desc_text, re.DOTALL)

                        sast_issue_desc = sast_desc_match.group(1).strip() if sast_desc_match else "N/A"
                        if sast_issue_desc != "N/A":
                            sast_issue_desc = re.sub(r'^(?:PAIR-)?[A-Fa-f0-9]{8}\s*-\s*', '', sast_issue_desc).strip()
                        dast_issue_desc = dast_desc_match.group(1).strip() if dast_desc_match else "N/A"

                        mitigation_clean_pattern = r'\n\[MITIGATION\]:\s*(.*)'
                        dast_issue_desc_clean = re.sub(mitigation_clean_pattern, '', dast_issue_desc).strip()
                        dast_issue_desc_clean = re.sub(r'\n\[BASE_SCORE\]:\s*(.*)', '', dast_issue_desc_clean).strip()
                        dast_issue_desc_clean = re.sub(r'<[^>]*>', '', dast_issue_desc_clean).strip()

                        mitigation_match = re.search(r'\[MITIGATION\]:\s*(.*)', raw_desc_text)
                        mitigation_val = mitigation_match.group(1).strip() if mitigation_match else "N/A"
                        if mitigation_val != "N/A":
                            mitigation_val = re.sub(r'<[^>]*>', '', mitigation_val).strip()

                        history_main_report.append({
                            "Pair ID": r_hist.get('key_id', 'N/A'),
                            "Final Severity": r_hist.get('predicted_severity', 'NONE'),
                            "Hybrid Score": f"{float(r_hist['predicted_score']):.2f}",
                            "CWE ID": r_hist.get('cwe_id', 'N/A'),
                            "Impacted Component": raw_comp_string,
                            "Vulnerability Description (SonarQube SAST)": sast_issue_desc,
                            "Vulnerability Description (OWASP ZAP DAST)": dast_issue_desc_clean,
                            "Mitigation Guidance (CWE)": mitigation_val
                        })
                    elif is_sast:
                        mitigation_match = re.search(r'\[MITIGATION\]:\s*(.*)', raw_desc_text, re.DOTALL)
                        mitigation_val = mitigation_match.group(1).strip() if mitigation_match else "N/A"
                        if mitigation_val != "N/A":
                            mitigation_val = re.sub(r'<[^>]*>', '', mitigation_val).strip()

                        clean_desc = re.sub(r'\n\[MITIGATION\]:.*$', '', raw_desc_text, flags=re.DOTALL).strip()
                        clean_desc = re.sub(r'\n\[(?:BASE_SCORE|SHAP_PRED|SHAP_BASE|SHAP_TOT_POS|SHAP_TOT_NEG|XAI_DESC|SHAP_POS|SHAP_NEG)\].*$', '', clean_desc, flags=re.DOTALL).strip()
                        clean_desc = re.sub(r'^(?:PAIR-)?[A-Fa-f0-9]{8}\s*-\s*', '', clean_desc).strip()
                        sast_issue_desc = re.sub(r'<[^>]*>', '', clean_desc).strip()

                        history_main_report.append({
                            "Key ID": r_hist.get('key_id', 'N/A'),
                            "Predicted Severity": r_hist.get('predicted_severity', 'NONE'),
                            "Predicted Score": f"{float(r_hist['predicted_score']):.2f}",
                            "CWE ID": r_hist.get('cwe_id', 'N/A'),
                            "Impacted Component": raw_comp_string,
                            "Vulnerability Description (SonarQube SAST)": sast_issue_desc
                        })
                    else:  # is_dast
                        mitigation_match = re.search(r'\[MITIGATION\]:\s*(.*)', raw_desc_text, re.DOTALL)
                        mitigation_val = mitigation_match.group(1).strip() if mitigation_match else "N/A"
                        if mitigation_val != "N/A":
                            mitigation_val = re.sub(r'<[^>]*>', '', mitigation_val).strip()

                        clean_desc = re.sub(r'\n\[MITIGATION\]:.*$', '', raw_desc_text, flags=re.DOTALL).strip()
                        clean_desc = re.sub(r'\n\[(?:BASE_SCORE|SHAP_PRED|SHAP_BASE|SHAP_TOT_POS|SHAP_TOT_NEG|XAI_DESC|SHAP_POS|SHAP_NEG)\].*$', '', clean_desc, flags=re.DOTALL).strip()
                        dast_issue_desc_clean = re.sub(r'<[^>]*>', '', clean_desc).strip()

                        history_main_report.append({
                            "Key ID": r_hist.get('key_id', 'N/A'),
                            "Predicted Severity": r_hist.get('predicted_severity', 'NONE'),
                            "Predicted Score": f"{float(r_hist['predicted_score']):.2f}",
                            "CWE ID": r_hist.get('cwe_id', 'N/A'),
                            "Impacted Component": raw_comp_string,
                            "Vulnerability Description (OWASP ZAP DAST)": dast_issue_desc_clean,
                            "Mitigation Guidance (CWE)": mitigation_val
                        })

                df_history_main_out = pd.DataFrame(history_main_report)
                csv_data_hist_main = df_history_main_out.to_csv(index=False)

                # Pemrosesan transparansi SHAP secara sinkron dengan indikator pemuatan
                cache_key = f"{selected_batch}_{'_'.join(sorted(severity_filter))}"

                with _SHAP_LOCK:
                    cached_result = _SHAP_CACHE.get(cache_key)

                if not cached_result or cached_result.get("status") != "ready":
                    with st.spinner("Memproses kalkulasi nilai transparansi SHAP"):
                        rows_data = df_filtered_sorted.to_dict('records')
                        _worker_compute_shap(cache_key, rows_data, is_hybrid, is_sast, is_dast, id_col_name)
                    with _SHAP_LOCK:
                        cached_result = _SHAP_CACHE.get(cache_key)

                if is_hybrid:
                    dl_label = "Export Laporan Korelasi Hybrid (.csv)"
                    dl_file = f"Laporan_Korelasi_Kerentanan_Hybrid_{selected_batch}.csv"
                    dl_shap_file = f"Laporan_Analisis_SHAP_Kerentanan_Hybrid_{selected_batch}.csv"
                elif is_sast:
                    dl_label = "Export Laporan Analisis SonarQube (.csv)"
                    dl_file = f"Laporan_Analisis_SonarQube_{selected_batch}.csv"
                    dl_shap_file = f"Laporan_Analisis_SHAP_SonarQube_{selected_batch}.csv"
                else:
                    dl_label = "Export Laporan Analisis OWASP ZAP (.csv)"
                    dl_file = f"Laporan_Analisis_OWASP_ZAP_{selected_batch}.csv"
                    dl_shap_file = f"Laporan_Analisis_SHAP_OWASP_ZAP_{selected_batch}.csv"

                col_dl1, col_dl2 = st.columns(2)
                with col_dl1:
                    st.download_button(
                        label=dl_label,
                        data=csv_data_hist_main,
                        file_name=dl_file,
                        mime="text/csv",
                        use_container_width=True,
                        key=f"btn_dl_hist_main_csv_{prefix_scanner(scanner_type)}_{selected_batch}"
                    )
                with col_dl2:
                    csv_shap_out = cached_result.get("csv_data_hist_shap", "") if cached_result else ""
                    st.download_button(
                        label="Export Laporan Analisis SHAP (.csv)",
                        data=csv_shap_out,
                        file_name=dl_shap_file,
                        mime="text/csv",
                        use_container_width=True,
                        key=f"btn_dl_hist_shap_csv_{prefix_scanner(scanner_type)}_{selected_batch}"
                    )

            col_btn1, col_btn2 = st.columns([1, 1])
            with col_btn1:
                if st.button(f"Hapus Session Terpilih", key=f"del_single_{prefix_scanner(scanner_type)}", use_container_width=True, help="Manajemen data histori"):
                    confirm_delete_batch_dialog(selected_batch)
            with col_btn2:
                if st.button(f"Hapus Seluruh History", key=f"clear_all_{prefix_scanner(scanner_type)}", use_container_width=True, help="Manajemen data histori"):
                    confirm_clear_all_dialog(scanner_type)
    except ApiError as e:
        st.error(f"Gagal memuat histori dari backend: {e}.")
    except Exception as e:
        st.error(f"Gagal memuat histori database: {e}.")
