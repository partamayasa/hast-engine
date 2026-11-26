# frontend/components/tab_sast.py
import streamlit as st
from frontend.components.auth_panel import processing_allowed
from frontend.utils.config import SAMPLE_SQ_URL, get_active_model
from frontend.utils.api_client import ApiError, ingest_report_cached
from frontend.components.history import render_embedded_history
from frontend.components.tab_shap_visual import render_tab_shap_visual


def render_tab_sast(run_analysis_flow, app_model=None):
    """Menampilkan konten tab SonarQube (SAST) dengan resolusi CWE-ID otomatis."""
    if not app_model:
        app_model = get_active_model()

    st.subheader("Analisis SonarQube (SAST)")

    allowed = processing_allowed()
    col_up, col_dl = st.columns(2)
    with col_up:
        uploaded_file_sq = st.file_uploader("Upload file laporan JSON SonarQube:", type=["json"], key="sq_upload",
                                            disabled=not allowed)
    with col_dl:
        st.markdown('<label style="font-size: 14px; font-weight: 400; margin-bottom: 8px; display: block;">Download contoh file laporan:</label>', unsafe_allow_html=True)
        st.link_button(
            label="Download Contoh Laporan SonarQube (.json)",
            url=SAMPLE_SQ_URL,
            use_container_width=True
        )

    if allowed and uploaded_file_sq is not None:
        if uploaded_file_sq.size > 50 * 1024 * 1024:
            st.error("Ukuran file SonarQube melebihi batas maksimum 50MB per file.")
        else:
            # v2: parsing, resolusi CWE, dan penyaringan cakupan berjalan di backend (/api/v1/ingest).
            try:
                parsed = ingest_report_cached("SAST", uploaded_file_sq.name, uploaded_file_sq.getvalue())
            except ApiError as e:
                st.error(f"Eror membaca file JSON SonarQube: {e}.")
            else:
                run_analysis_flow("SonarQube (SAST)", "SAST", parsed["records"], target_domain_input="", is_button_enabled=True)
    render_embedded_history("SonarQube (SAST)", app_model=app_model)
    render_tab_shap_visual(app_model=app_model, scanner="SAST")
