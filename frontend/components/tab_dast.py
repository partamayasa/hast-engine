# frontend/components/tab_dast.py
import streamlit as st
from frontend.utils.config import SAMPLE_ZAP_URL, get_active_model
from frontend.utils.api_client import ApiError, ingest_report_cached
from frontend.components.history import render_embedded_history
from frontend.components.tab_shap_visual import render_tab_shap_visual


def render_tab_dast(run_analysis_flow, app_model=None):
    """Menampilkan konten tab OWASP ZAP (DAST)."""
    if not app_model:
        app_model = get_active_model()

    st.subheader("Analisis OWASP ZAP (DAST)")

    col_up, col_dl = st.columns(2)
    with col_up:
        uploaded_file_zap = st.file_uploader("Upload file laporan JSON OWASP ZAP:", type=["json"], key="zap_upload")
    with col_dl:
        st.markdown('<label style="font-size: 14px; font-weight: 400; margin-bottom: 8px; display: block;">Download contoh file laporan:</label>', unsafe_allow_html=True)
        st.link_button(
            label="Download Contoh Laporan OWASP ZAP (.json)",
            url=SAMPLE_ZAP_URL,
            use_container_width=True
        )

    if uploaded_file_zap is not None:
        if uploaded_file_zap.size > 50 * 1024 * 1024:
            st.error("Ukuran file OWASP ZAP melebihi batas maksimum 50MB per file.")
        else:
            # v2: parsing, resolusi CWE, dan penyaringan cakupan berjalan di backend (/api/v1/ingest).
            try:
                parsed = ingest_report_cached("DAST", uploaded_file_zap.name, uploaded_file_zap.getvalue())
            except ApiError as e:
                st.error(f"Eror membaca file JSON OWASP ZAP: {e}.")
            else:
                run_analysis_flow("OWASP ZAP (DAST)", "DAST", parsed["records"], target_domain_input="", is_button_enabled=True)
    render_embedded_history("OWASP ZAP (DAST)", app_model=app_model)
    render_tab_shap_visual(app_model=app_model, scanner="DAST")
