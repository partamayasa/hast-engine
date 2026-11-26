# frontend/app.py
"""
Titik masuk Streamlit (v2): navigasi multipage yang dikelompokkan menurut alur kerja.

UI adalah klien tipis: setiap baca/tulis data melewati backend FastAPI (frontend/utils/api_client.py).
Rute yang dipertahankan dari v1: ?dev=true / ?test_mode=true / ?qa=true (halaman riset).
"""
import os
import sys

FRONTEND_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(FRONTEND_DIR, ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import streamlit as st  # noqa: E402

from frontend.components.analysis_flow import run_analysis_flow  # noqa: E402
from frontend.components.auth_panel import (  # noqa: E402
    can,
    current_user,
    init_session,
    render_page_account,
    render_page_login,
    render_page_logout,
)
from frontend.components.page_dashboard import render_page_dashboard  # noqa: E402
from frontend.components.page_decision_log import render_page_decision_log  # noqa: E402
from frontend.components.page_priority import render_page_priority  # noqa: E402
from frontend.components.page_dss_research import render_page_dss_research  # noqa: E402
from frontend.components.page_dss_weights import render_page_dss_weights  # noqa: E402
from frontend.components.page_users import render_page_users  # noqa: E402
from frontend.components.tab_analysis import render_tab_analysis  # noqa: E402
from frontend.components.tab_blackbox_testing import render_tab_blackbox_testing  # noqa: E402
from frontend.components.tab_dast import render_tab_dast  # noqa: E402
from frontend.components.tab_hybrid import render_tab_hybrid  # noqa: E402
from frontend.components.tab_sast import render_tab_sast  # noqa: E402
from frontend.components.tab_simulation import render_tab_simulation  # noqa: E402
from frontend.utils.config import get_application_version, load_app_config  # noqa: E402

TRUTHY = ["true", "1", "yes"]

config_data = load_app_config()
(app_title_backend, app_version_backend, app_description_backend, app_er_backend, app_model_backend,
 is_api_online, app_dataset_backend) = get_application_version()

app_title = app_title_backend if is_api_online else config_data.get("api_title", "N/A")
app_version = app_version_backend if is_api_online else "N/A"
app_description = app_description_backend if is_api_online else config_data.get("api_description", "N/A")
app_model = app_model_backend if is_api_online else "N/A"
app_er = app_er_backend if is_api_online else "N/A"
raw_dataset = app_dataset_backend if is_api_online else "N/A"
app_dataset = raw_dataset.replace("-", "").split("T")[0] if raw_dataset and raw_dataset != "N/A" else "N/A"

st.set_page_config(page_title=app_title, layout="wide")
# Pulihkan login dari cookie, akhiri sesi kedaluwarsa, dan jalankan operasi cookie sebelum menu dibangun.
init_session()

query_params = st.query_params
# Mode pengembang/riset diminta lewat URL dan dipertahankan selama sesi (tautan halaman menghapus query param).
if any(str(query_params.get(p, "")).lower() in TRUTHY for p in ("test_mode", "dev", "qa")):
    st.session_state["dev_mode"] = True
is_test_mode = bool(st.session_state.get("dev_mode"))

st.title(app_title)
st.write(app_description)
if not is_api_online:
    st.error("Backend FastAPI tidak dapat dihubungi. Sebagian besar halaman memerlukan backend yang aktif.")

pages = {
    "Keputusan": [
        st.Page(render_page_dashboard, title="Dashboard", url_path="dasbor", default=True),
        st.Page(render_page_priority, title="Prioritas Perbaikan", url_path="prioritas"),
        st.Page(render_page_decision_log, title="Decision History", url_path="riwayat"),
    ],
    "Scan Data": [
        st.Page(lambda: render_tab_sast(run_analysis_flow, app_model=app_model), title="1. SonarQube (SAST)",
                url_path="sast"),
        st.Page(lambda: render_tab_dast(run_analysis_flow, app_model=app_model), title="2. OWASP ZAP (DAST)",
                url_path="dast"),
        st.Page(lambda: render_tab_hybrid(app_model=app_model), title="3. Korelasi Hybrid", url_path="hybrid"),
    ],
}
if can("users.manage"):
    pages["Administrasi"] = [st.Page(render_page_users, title="User", url_path="pengguna")]
if is_test_mode:
    pages["Riset & QA (Dev)"] = [
        st.Page(render_page_dss_weights, title="Priority Settings", url_path="pengaturan"),
        st.Page(lambda: render_tab_analysis(app_model=app_model), title="Analisis Riset", url_path="riset"),
        st.Page(render_page_dss_research, title="Sensitivitas & Evaluasi DSS", url_path="riset-dss"),
        st.Page(lambda: render_tab_simulation(app_model=app_model), title="Simulasi & Pengujian Interaktif",
                url_path="simulasi"),
        st.Page(lambda: render_tab_blackbox_testing(app_model=app_model), title="Pengujian Black-Box",
                url_path="blackbox"),
    ]

# Menu Akun sejajar di baris menu header navigasi atas (mepet kiri bersama menu lain)
user = current_user()
if user:
    pages["Akun"] = [
        st.Page(render_page_account, title=f"Profil ({user.get('username')})", url_path="akun"),
        st.Page(render_page_logout, title="Logout", url_path="logout"),
    ]
else:
    pages["Akun"] = [
        st.Page(render_page_login, title="Login", url_path="login"),
    ]

st.navigation(pages, position="top").run()

st.markdown("---")
col_foot1, col_foot2 = st.columns([0.45, 0.55])
with col_foot1:
    st.caption(f"{app_title}{' | [Dev Mode Active]' if is_test_mode else ''}")
with col_foot2:
    st.markdown(
        f"<p style='text-align: right; color: #7f8c8d; font-size: 14px; margin: 0;'>Dataset: {app_dataset} - "
        f"Escalation Rate: {app_er} - Model: {app_model} - Version: {app_version}</p>",
        unsafe_allow_html=True
    )
