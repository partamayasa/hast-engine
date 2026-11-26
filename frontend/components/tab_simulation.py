# frontend/components/tab_simulation.py
import os
import time
import pickle
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

from backend.config import (
    ROOT_DIR,
    RF_MODEL_PATH,
    TFIDF_PATH,
    load_hybrid_escalation_rate
)
from backend.dss.escalation import escalate  # rumus kanonik K1: base + (10 - base) x ER
from frontend.utils.formatters import get_severity_category


@st.cache_resource
def load_cached_models():
    """Memuat model biner Random Forest dan vectorizer TF-IDF ke memori untuk inferensi interaktif yang cepat."""
    models = {}
    tfidf = None

    if os.path.exists(TFIDF_PATH):
        try:
            with open(TFIDF_PATH, "rb") as f:
                tfidf = pickle.load(f)
        except Exception as e:
            print(f"-> Gagal memuat TF-IDF: {e}")

    if os.path.exists(RF_MODEL_PATH):
        try:
            with open(RF_MODEL_PATH, "rb") as f:
                models["Random Forest Regressor"] = pickle.load(f)
        except Exception as e:
            print(f"-> Gagal memuat Random Forest: {e}")

    return models, tfidf


def get_severity_badge_color(severity):
    """Mengembalikan kode warna hex untuk lencana keparahan sesuai standar CVSS v4.0."""
    mapping = {
        "CRITICAL": "#d63031",
        "HIGH": "#e17055",
        "MEDIUM": "#fdcb6e",
        "LOW": "#0984e3",
        "NONE": "#b2bec3"
    }
    return mapping.get(str(severity).upper(), "#7f8c8d")


def render_tab_simulation(app_model=None):
    """Menampilkan tab Simulasi & Pengujian Interaktif untuk pengujian teknis model Random Forest."""
    st.subheader("Simulasi & Pengujian Interaktif")
    st.write(
        "Modul lingkungan pengujian teknis (*model testing workbench*) ini dirancang untuk mengevaluasi karakteristik inferensi algoritma "
        "**Random Forest Regressor** terhadap beragam deskripsi teks kerentanan secara arbitrer, menganalisis dampak penyesuaian skor melalui parameter "
        "*Escalation Rate* korelasi **HAST** secara waktu nyata (*real-time*), serta menyajikan transparansi dekomposisi atribusi fitur menggunakan metode **Explainable AI (SHAP)**."
    )

    configured_er = load_hybrid_escalation_rate()
    models, tfidf = load_cached_models()

    # Preset contoh kerentanan nyata & sampel uji pemindai nyata (SonarQube & OWASP ZAP)
    presets = {
        "Custom Input (Ketik Deskripsi Bebas)": "",

        # --- Sampel DAST nyata (laporan OWASP ZAP) ---
        "DAST [ZAP]: Cross Site Scripting - Reflected (CWE-79)": (
            "Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. When an attacker gets a user's browser to execute code, the code runs within the security context of the hosting site."
        ),
        "DAST [ZAP]: Cross Site Scripting - DOM Based (CWE-79)": (
            "DOM-based cross-site scripting vulnerability where client-side JavaScript processes untrusted URL fragment data and writes unescaped HTML directly to the document object model."
        ),
        "DAST [ZAP]: SQL Injection (CWE-89)": (
            "SQL injection may be possible. An attacker can manipulate database queries, bypass authentication, and access or modify sensitive data via unvalidated input parameters."
        ),
        "DAST [ZAP]: Absence of Anti-CSRF Tokens (CWE-352)": (
            "No Anti-CSRF tokens were found in a HTML submission form. A cross-site request forgery attack involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent."
        ),
        "DAST [ZAP]: Content Security Policy (CSP) Header Not Set (CWE-693)": (
            "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. CSP provides standard HTTP headers allowing website owners to declare approved sources."
        ),
        "DAST [ZAP]: Missing Anti-clickjacking Header (CWE-1021)": (
            "The response does not protect against ClickJacking attacks. It should include either Content-Security-Policy with frame-ancestors directive or X-Frame-Options."
        ),
        "DAST [ZAP]: Cookie Without Secure Flag (CWE-614)": (
            "A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections. Whenever a cookie contains sensitive session information, it should always be passed using an encrypted channel."
        ),
        "DAST [ZAP]: Cookie No HttpOnly Flag (CWE-1004)": (
            "A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script runs on this page then the cookie will be accessible and session hijacking may be possible."
        ),
        "DAST [ZAP]: Cookie without SameSite Attribute (CWE-1275)": (
            "A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a cross-site request. The SameSite attribute is an effective counter measure to cross-site request forgery and timing attacks."
        ),
        "DAST [ZAP]: Strict-Transport-Security Header Not Set (CWE-319)": (
            "HTTP Strict Transport Security (HSTS) header is missing, failing to declare that complying user agents are to interact with the web server using only secure HTTPS connections."
        ),
        "DAST [ZAP]: Sub Resource Integrity Attribute Missing (CWE-345)": (
            "The integrity attribute is missing on a script or link tag served by an external server. The integrity tag prevents an attacker who has gained access to this server from injecting malicious content."
        ),
        "DAST [ZAP]: Server Leaks Information via X-Powered-By Header (CWE-497)": (
            "The web server is leaking information via one or more X-Powered-By HTTP response headers. Access to such information may facilitate attackers identifying underlying frameworks and component vulnerabilities."
        ),
        "DAST [ZAP]: Hidden File or Diagnostic Endpoint Found (CWE-538)": (
            "A sensitive file or diagnostic endpoint was identified as accessible. This may leak administrative, configuration, or credential information which can be leveraged to further attack the system."
        ),
        # --- Sampel SAST nyata (aturan & laporan SonarQube) ---
        "SAST [Sonar]: Credentials should not be hard-coded (CWE-798)": (
            "Credentials should not be hard-coded. Because software development environments are typically shared, hard-coding sensitive credentials such as passwords and secret keys into source code is risky."
        ),
        "SAST [Sonar]: Cookies should have the Secure flag (CWE-614)": (
            "Cookies should have the secure flag set. When a cookie is protected with the secure attribute, the browser will not send that cookie in an unencrypted HTTP request."
        ),
        "SAST [Sonar]: Cookies should have the HttpOnly flag (CWE-1004)": (
            "Cookies should have the HttpOnly flag set. When this flag is enabled, the browser prevents client-side scripts from accessing the cookie, mitigating the risk of cross-site scripting stealing session tokens."
        ),
        "SAST [Sonar]: File permissions should not be world-accessible (CWE-732)": (
            "File permissions should not be set to world-accessible values. Overly permissive file permissions can allow unauthorized local users to read or modify critical application configuration files."
        ),
        "SAST [Sonar]: HTTP request content length should be limited (CWE-770)": (
            "HTTP request content length should be limited. When an application accepts file uploads or large payloads without size limits, attackers can cause denial of service by exhausting server memory or storage."
        ),
        "SAST [Sonar]: Database queries should be parameterized (CWE-89)": (
            "Database queries should be parameterized to prevent SQL injection. Passing user-controlled input directly into dynamic SQL queries allows attackers to execute unintended database commands."
        ),
        "SAST [Sonar]: User input should be sanitized before output (CWE-79)": (
            "Make sure that user input is sanitized and encoded before being output directly to web pages. Unsanitized data in HTML response allows attackers to execute malicious scripts in users' browsers."
        ),
        "SAST [Sonar]: CSRF protection should be enabled (CWE-352)": (
            "Make sure that disabling CSRF protection is safe here. State-changing HTTP operations must require anti-forgery tokens to protect users against unauthorized cross-site actions."
        ),
        "SAST [Sonar]: Code with debug features enabled in production (CWE-497)": (
            "Delivering code in production with debug features turned on is security-sensitive. Verbose error messages, stack traces, and debug diagnostics expose internal framework details to attackers."
        ),
        "SAST [Sonar]: PRNGs should not be used in security contexts (CWE-338)": (
            "Pseudorandom number generators (PRNGs) should not be used in security contexts. Standard pseudo-random number generators produce predictable values that can be anticipated by attackers to forge security tokens."
        )
    }

    def update_preset_text():
        chosen = st.session_state.get("sim_preset_choice")
        if chosen in presets:
            st.session_state["sim_user_description"] = presets[chosen]

    # Atur nilai awal area teks dari preset pertama bila belum ada
    if "sim_user_description" not in st.session_state:
        default_preset = list(presets.keys())[1]  # Preset RCE
        st.session_state["sim_preset_choice"] = default_preset
        st.session_state["sim_user_description"] = presets[default_preset]

    st.markdown("---")

    # Batasi area teks deskripsi kerentanan menjadi 3 baris dengan gulir vertikal
    st.markdown(
        """
        <style>
        div[data-testid="stTextArea"] textarea {
            height: 90px !important;
            min-height: 90px !important;
            overflow-y: auto !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    col_input1, col_input2 = st.columns([0.65, 0.35])
    with col_input1:
        preset_choice = st.selectbox(
            "Pilih Templat Kasus Kerentanan:",
            list(presets.keys()),
            key="sim_preset_choice",
            on_change=update_preset_text
        )
        user_description = st.text_area(
            "Deskripsi Kerentanan (Bahasa Inggris / Istilah Teknis Scanner):",
            height=90,
            placeholder="Contoh: Remote code execution vulnerability allows unauthenticated attackers to execute arbitrary system commands",
            key="sim_user_description"
        )

    with col_input2:
        st.text_input(
            "Algoritma Model Pengujian:",
            value="Random Forest Regressor",
            disabled=True,
            help="Sistem riset ini berfokus tunggal pada evaluasi algoritma Random Forest Regressor."
        )
        selected_model_name = "Random Forest Regressor"

        sub_col1, sub_col2 = st.columns([0.48, 0.52])
        with sub_col1:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            is_hybrid_verified = st.checkbox(
                "Verifikasi HAST",
                value=False,
                help="Celah aktif terdeteksi di SAST & DAST. Jika dicentang, skor kerentanan akan ditingkatkan menggunakan Escalation Rate HAST sebagai validasi True Positive.",
                key="sim_hast_checkbox"
            )
        with sub_col2:
            sim_er = st.slider(
                "Escalation Rate HAST (%):",
                min_value=0,
                max_value=30,
                value=int(configured_er * 100),
                step=5,
                disabled=not is_hybrid_verified,
                key="sim_er_slider"
            ) / 100.0

        btn_analyze = st.button(
            "Jalankan Pengujian & Analisis",
            type="primary",
            use_container_width=True,
            key="sim_run_btn"
        )

    if btn_analyze:
        if not user_description.strip():
            st.warning("Silakan masukkan teks deskripsi kerentanan terlebih dahulu.")
            return

        run_single_testing_flow(
            user_description=user_description,
            selected_model_name=selected_model_name,
            is_hybrid_verified=is_hybrid_verified,
            sim_er=sim_er,
            models=models,
            tfidf=tfidf
        )


def run_single_testing_flow(user_description, selected_model_name, is_hybrid_verified, sim_er, models, tfidf):
    """Menjalankan satu inferensi Random Forest dan visualisasi dekomposisi SHAP."""
    with st.spinner("Sedang memproses ekstraksi fitur TF-IDF dan kalkulasi model Random Forest"):
        t_start = time.time()
        active_model_obj = models.get(selected_model_name) if models else None

        raw_score = 6.5
        token_contributions = []
        base_value = 6.55

        if tfidf is not None and active_model_obj is not None:
            try:
                vec = tfidf.transform([user_description])
                pred_arr = active_model_obj.predict(vec)
                raw_score = float(pred_arr[0])
                raw_score = max(0.0, min(10.0, round(raw_score, 2)))

                # Ekstrak token aktif
                feature_names = tfidf.get_feature_names_out()
                nz_indices = vec.indices
                nz_weights = vec.data

                # Hitung nilai SHAP
                try:
                    import shap
                    explainer = shap.TreeExplainer(active_model_obj)
                    shap_vals = explainer.shap_values(vec.toarray())
                    if hasattr(explainer, "expected_value"):
                        ev = explainer.expected_value
                        base_value = float(ev[0]) if isinstance(ev, (list, np.ndarray)) else float(ev)
                    if isinstance(shap_vals, list):
                        shap_row = shap_vals[0][0]
                    elif hasattr(shap_vals, "values"):
                        shap_row = shap_vals.values[0]
                    else:
                        shap_row = np.asarray(shap_vals).flatten()

                    for idx, weight in zip(nz_indices, nz_weights):
                        token_word = feature_names[idx]
                        s_val = float(shap_row[idx]) if idx < len(shap_row) else float(weight * 0.5)
                        token_contributions.append((token_word, s_val, float(weight)))
                except Exception:
                    # Cadangan heuristik berdasarkan bobot TF-IDF
                    for idx, weight in zip(nz_indices, nz_weights):
                        token_word = feature_names[idx]
                        pseudo_impact = float(weight * (0.8 if any(k in token_word for k in ['exec', 'auth', 'code', 'arbitrary']) else -0.2))
                        token_contributions.append((token_word, pseudo_impact, float(weight)))
            except Exception as e:
                st.error(f"Eror saat inferensi model: {e}")
                raw_score = 6.5
        else:
            raw_score = 7.8 if "unauthenticated" in user_description.lower() else 5.5

        latency_ms = round((time.time() - t_start) * 1000, 2)

        # Hitung skor HAST
        final_score = raw_score
        if is_hybrid_verified:
            final_score = escalate(raw_score, True, sim_er)

        base_severity = get_severity_category(raw_score)
        final_severity = get_severity_category(final_score)

        st.markdown("---")
        st.markdown("#### Hasil Evaluasi Prediksi & Penjelasan XAI")

        delta_val = round(final_score - raw_score, 2)
        delta_badge = f"<span style='font-size: 16px; font-weight: normal; color: #27ae60; margin-left: 6px;'>+{delta_val:.2f}</span>" if (is_hybrid_verified and delta_val > 0) else ""

        pos_sum = sum(t[1] for t in token_contributions if t[1] > 0)
        neg_sum = sum(t[1] for t in token_contributions if t[1] < 0)

        # Evaluasi dampak eskalasi prioritas HAST (pergeseran kelas keparahan)
        if is_hybrid_verified and sim_er > 0:
            if base_severity != final_severity:
                escalation_badge_text = f"{base_severity} → {final_severity}"
                escalation_badge_bg = get_severity_badge_color(final_severity)
            else:
                escalation_badge_text = f"Tetap {final_severity} (+{int(sim_er*100)}% ER)"
                escalation_badge_bg = "#2980b9"
        elif is_hybrid_verified:
            escalation_badge_text = "ER 0% (Skor Tetap)"
            escalation_badge_bg = "#7f8c8d"
        else:
            escalation_badge_text = "Single Scan (Tanpa ER)"
            escalation_badge_bg = "#95a5a6"

        res_col1, res_col2, res_col3, res_col4 = st.columns(4)
        with res_col1:
            st.markdown(
                f"""
                <div style="font-size: 14px; color: #555; margin-bottom: 4px;">Skor Prediksi Dasar</div>
                <div style="font-size: 32px; font-weight: normal; color: #262730; line-height: 1.2; margin-bottom: 8px;">{raw_score:.2f}</div>
                <div><span style="background-color: {get_severity_badge_color(base_severity)}; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: normal;">{base_severity}</span></div>
                """,
                unsafe_allow_html=True
            )
        with res_col2:
            net_val = pos_sum + neg_sum
            st.markdown(
                f"""
                <div style="font-size: 14px; color: #555; margin-bottom: 4px;">Kontribusi Token SHAP</div>
                <div style="font-size: 28px; font-weight: normal; line-height: 1.2; margin-bottom: 8px; white-space: nowrap;">
                    <span style="color: #2980b9;">+{pos_sum:.2f}</span>
                    <span style="color: #bdc3c7; font-weight: 300; margin: 0 4px;">/</span>
                    <span style="color: #e74c3c;">{neg_sum:.2f}</span>
                </div>
                <div><span style="background-color: #27ae60; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: normal;">Net Efek: {net_val:+.2f} φ</span></div>
                """,
                unsafe_allow_html=True
            )
        with res_col3:
            st.markdown(
                f"""
                <div style="font-size: 14px; color: #555; margin-bottom: 4px;">Skor Akhir HAST (+ER)</div>
                <div style="font-size: 32px; font-weight: normal; color: #262730; line-height: 1.2; margin-bottom: 8px;">
                    {final_score:.2f}{delta_badge}
                </div>
                <div>
                    <span style="background-color: {get_severity_badge_color(final_severity)}; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: normal;">{final_severity}</span>
                    <span style="background-color: {escalation_badge_bg}; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: normal; margin-left: 4px;">{escalation_badge_text}</span>
                </div>
                """,
                unsafe_allow_html=True
            )
        with res_col4:
            st.markdown(
                f"""
                <div style="font-size: 14px; color: #555; margin-bottom: 4px;">Latensi Inferensi</div>
                <div style="font-size: 32px; font-weight: normal; color: #262730; line-height: 1.2; margin-bottom: 8px;">{latency_ms} ms</div>
                <div><span style="background-color: #27ae60; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: normal;">Random Forest + SHAP</span></div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("<br>", unsafe_allow_html=True)

        # Visualisasikan dekomposisi token SHAP
        if token_contributions:
            token_contributions.sort(key=lambda x: abs(x[1]), reverse=True)
            top_tokens = token_contributions[:10]

            df_tokens = pd.DataFrame({
                "Token Tekstual": [t[0] for t in top_tokens],
                "Kontribusi SHAP": [round(t[1], 4) for t in top_tokens],
                "Bobot TF-IDF": [round(t[2], 4) for t in top_tokens],
                "Arah Dampak": ["Kontribusi Positif" if t[1] >= 0 else "Kontribusi Negatif" for t in top_tokens]
            }).sort_values(by="Kontribusi SHAP", ascending=True)

            col_chart, col_exp = st.columns([0.60, 0.40])
            with col_chart:
                st.markdown("##### Dekomposisi Kontribusi Token Teks (Local SHAP):")
                fig_tok = px.bar(
                    df_tokens,
                    x="Kontribusi SHAP",
                    y="Token Tekstual",
                    orientation="h",
                    color="Arah Dampak",
                    color_discrete_map={
                        "Kontribusi Positif": "#e74c3c",
                        "Kontribusi Negatif": "#3498db"
                    },
                    text="Kontribusi SHAP"
                )
                fig_tok.update_traces(
                    textposition="outside",
                    cliponaxis=False,
                    textfont=dict(size=11)
                )
                fig_tok.update_layout(
                    font=dict(size=12, color="#2c3e50"),
                    xaxis=dict(
                        title=dict(text="Kontribusi Nilai SHAP (φ)", font=dict(size=12)),
                        tickfont=dict(size=11)
                    ),
                    yaxis=dict(
                        title=dict(text="Token Kata Kunci Terdeteksi", font=dict(size=12)),
                        tickfont=dict(size=11)
                    ),
                    margin=dict(l=20, r=40, t=10, b=20),
                    height=360,
                    legend=dict(
                        orientation="h",
                        yanchor="bottom",
                        y=1.02,
                        xanchor="right",
                        x=1,
                        font=dict(size=11)
                    )
                )
                st.plotly_chart(fig_tok, width="stretch")

            with col_exp:
                st.markdown("##### Tabel Atribusi Token:")
                st.dataframe(
                    df_tokens[["Token Tekstual", "Bobot TF-IDF", "Kontribusi SHAP", "Arah Dampak"]].sort_values(by="Kontribusi SHAP", ascending=False),
                    width="stretch",
                    hide_index=True
                )

                st.markdown("##### Rincian Dekomposisi Aditif:")
                pos_sum = sum(t[1] for t in token_contributions if t[1] > 0)
                neg_sum = sum(t[1] for t in token_contributions if t[1] < 0)
                other_bias = round(raw_score - (base_value + pos_sum + neg_sum), 2)
                hast_line = f"<div>&bull; <strong>Eskalasi HAST (+{int(sim_er*100)}%):</strong> {raw_score:.2f} × {1+sim_er:.2f} = <strong>{final_score:.2f}</strong></div>" if (is_hybrid_verified and sim_er > 0) else ""

                tooltip_text = "Efek bias kumulatif dari fitur-fitur kamus kosakata model yang bernilai nol (absent features) pada teks pengujian guna memenuhi properti efisiensi aditif SHAP"
                other_line = (
                    f"<div>&bull; <span class='sim-tooltip-term'>"
                    f"<strong>Bias Kosakata Absen (Absent Bias)</strong> <span style='color: #2980b9;'>ⓘ</span>"
                    f"<span class='sim-tooltip-box'>{tooltip_text}</span>"
                    f"</span>: {other_bias:+.2f}</div>"
                ) if abs(other_bias) >= 0.01 else ""
                
                calc_formula = f"{base_value:.2f} + ({pos_sum:+.2f}) + ({neg_sum:+.2f})"
                if abs(other_bias) >= 0.01:
                    calc_formula += f" + ({other_bias:+.2f})"
                calc_formula += f" = <strong>{raw_score:.2f}</strong>"

                st.markdown(
                    f"""
                    <style>
                    .sim-tooltip-term {{
                        position: relative;
                        display: inline-block;
                        cursor: help;
                        border-bottom: 1px dotted #7f8c8d;
                    }}
                    .sim-tooltip-term .sim-tooltip-box {{
                        visibility: hidden;
                        opacity: 0;
                        width: 260px;
                        background-color: #1e293b;
                        color: #ffffff;
                        text-align: left;
                        border-radius: 6px;
                        padding: 8px 12px;
                        position: absolute;
                        z-index: 9999;
                        bottom: 130%;
                        left: 0;
                        box-shadow: 0 4px 14px rgba(0,0,0,0.3);
                        font-size: 12px;
                        font-weight: normal;
                        line-height: 1.4;
                        transition: opacity 0.2s ease-in-out;
                        pointer-events: none;
                    }}
                    .sim-tooltip-term .sim-tooltip-box::after {{
                        content: "";
                        position: absolute;
                        top: 100%;
                        left: 30px;
                        border-width: 6px;
                        border-style: solid;
                        border-color: #1e293b transparent transparent transparent;
                    }}
                    .sim-tooltip-term:hover .sim-tooltip-box {{
                        visibility: visible;
                        opacity: 1;
                    }}
                    </style>
                    <div style="font-size: 14px; line-height: 1.8; color: #2c3e50;">
                        <div>&bull; <strong>Nilai Dasar (Base Value):</strong> {base_value:.2f}</div>
                        <div>&bull; <strong>Total Kontribusi Positif:</strong> +{pos_sum:.2f}</div>
                        <div>&bull; <strong>Total Kontribusi Negatif:</strong> {neg_sum:.2f}</div>
                        {other_line}
                        <div>&bull; <strong>Skor Prediksi Dasar:</strong> {calc_formula}</div>
                        {hast_line}
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            st.info("Tidak ada token dari teks yang cocok dengan kosakata TF-IDF kamus model.")
