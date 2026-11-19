# frontend/components/auth_panel.py
"""Login / logout di sidebar. JWT disimpan di st.session_state dan dikirim oleh api_client."""
import html

import streamlit as st

from frontend.utils.api_client import ApiError, login

# Label cadangan untuk tampilan; label dan hak akses resmi berasal dari backend (/api/v1/roles, respons login).
ROLE_LABELS = {
    "admin": "Administrator",
    "manager": "Manajer Keamanan",
    "analyst": "Analis Keamanan",
    "developer": "Pengembang",
    "auditor": "Auditor",
}


def current_user() -> dict | None:
    return st.session_state.get("auth_user")


def can(permission: str) -> bool:
    """True bila peran pengguna yang login memiliki hak `permission` (daftar dikirim backend saat login)."""
    u = current_user()
    return bool(u and permission in (u.get("permissions") or []))


def is_manager() -> bool:
    """Dipertahankan untuk kompatibilitas: boleh mengubah pengaturan prioritas."""
    return can("settings.manage")


def render_auth_panel() -> None:
    with st.sidebar:
        st.markdown("### Akun")
        user = current_user()
        if user:
            name = user.get('full_name') or user['username']
            role = user.get('role_label') or ROLE_LABELS.get(user['role'], user['role'])
            label = name if name == role else f"{name} · {role}"
            # Badge satu baris (lebih ringkas dari st.success); teks panjang dipotong dengan elipsis, utuh di tooltip.
            st.markdown(
                "<div title='Login sebagai {t}' style='padding:6px 10px;border-radius:8px;font-size:0.85rem;"
                "line-height:1.3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"
                "background:rgba(33,195,84,0.15);color:inherit;margin-bottom:8px;'>"
                "<span style='color:rgb(33,195,84);'>&#10003;</span> Login: <b>{t}</b></div>".format(t=html.escape(label)),
                unsafe_allow_html=True,
            )
            if st.button("Logout", use_container_width=True):
                st.session_state.pop("auth_token", None)
                st.session_state.pop("auth_user", None)
                st.rerun()
            return
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login", use_container_width=True)
        if submitted:
            try:
                res = login(username, password)
            except ApiError as e:
                st.error(str(e))
            else:
                st.session_state["auth_token"] = res["access_token"]
                st.session_state["auth_user"] = res["user"]
                st.rerun()


def require_login(message: str = "Halaman ini memerlukan login. Silakan login melalui panel samping.") -> bool:
    if current_user() is None:
        st.info(message)
        return False
    return True
