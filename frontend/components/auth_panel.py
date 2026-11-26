# frontend/components/auth_panel.py
"""
Login / logout melalui menu "Akun" di navigasi atas. JWT disimpan di st.session_state dan dikirim oleh api_client.

Agar login bertahan ketika halaman dimuat ulang, token juga disimpan sebagai cookie browser (`hast_session`) dengan umur
sama dengan sisa masa berlaku token. init_session() dipanggil app.py pada setiap run: memulihkan login dari cookie
pada sesi Streamlit baru (divalidasi ke /api/v1/auth/me), mengakhiri sesi yang tokennya kedaluwarsa
(HAST_JWT_EXPIRE_MINUTES di backend), dan menulis/menghapus cookie yang tertunda. Logout menghapus cookie.
"""
import base64
import html
import json
import time

import streamlit as st

from frontend.utils.api_client import ApiError, login, me_with_token

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


LOGIN_HINT = "menu Akun di header navigasi atas"
SESSION_COOKIE = "hast_session"


# ---------------------------------------------------------------------------
# Sesi login yang bertahan saat halaman dimuat ulang (fungsi murni diuji tanpa Streamlit)
# ---------------------------------------------------------------------------
def token_expiry(token: str | None) -> float | None:
    """Mengembalikan waktu kedaluwarsa (epoch detik) dari klaim `exp` JWT tanpa memverifikasi tanda tangan."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload))["exp"])
    except Exception:
        return None


def seconds_left(token: str | None, now: float | None = None) -> int:
    """Sisa masa berlaku token dalam detik (0 bila kedaluwarsa atau tidak terbaca)."""
    exp = token_expiry(token)
    if exp is None:
        return 0
    return max(0, int(exp - (now if now is not None else time.time())))


def cookie_script(token: str | None, max_age: int, secure: bool) -> str:
    """Skrip yang menulis (max_age > 0) atau menghapus (max_age = 0) cookie sesi di browser."""
    value = json.dumps(token or "")[1:-1]
    attrs = f"Path=/; Max-Age={max(0, int(max_age))}; SameSite=Strict" + ("; Secure" if secure else "")
    return f'<script>document.cookie = "{SESSION_COOKIE}={value}; {attrs}";</script>'


def _is_https() -> bool:
    try:
        return str(st.context.url).lower().startswith("https://")
    except Exception:
        return False


def _set_session(token: str, user: dict, remember: bool = False) -> None:
    st.session_state["auth_token"] = token
    st.session_state["auth_user"] = user
    st.session_state.pop("session_expired", None)
    if remember:
        st.session_state["cookie_set_pending"] = token


def _end_session(expired: bool) -> None:
    st.session_state.pop("auth_token", None)
    st.session_state.pop("auth_user", None)
    st.session_state["cookie_clear_pending"] = True
    # Cookie pada permintaan awal sesi ini masih terbaca; jangan pulihkan lagi dalam sesi yang sama.
    st.session_state["skip_cookie_restore"] = True
    if expired:
        st.session_state["session_expired"] = True


def _restore_from_cookie() -> None:
    """Memulihkan login dari cookie pada sesi Streamlit baru (mis. setelah halaman dimuat ulang)."""
    if st.session_state.get("auth_token") or st.session_state.get("skip_cookie_restore"):
        return
    st.session_state["skip_cookie_restore"] = True  # cukup sekali per sesi
    try:
        token = st.context.cookies.get(SESSION_COOKIE)
    except Exception:
        token = None
    if not token:
        return
    if seconds_left(token) <= 0:
        st.session_state["cookie_clear_pending"] = True
        return
    try:
        user = me_with_token(token)
    except ApiError:
        st.session_state["cookie_clear_pending"] = True
        return
    _set_session(token, user)


def _enforce_expiry() -> None:
    """Mengakhiri sesi ketika masa berlaku token habis, walaupun belum ada permintaan ke API."""
    token = st.session_state.get("auth_token")
    if token and seconds_left(token) <= 0:
        _end_session(expired=True)


def _flush_cookie_ops() -> None:
    """Menjalankan penulisan/penghapusan cookie yang tertunda (dilakukan pada run berikutnya setelah st.rerun)."""
    pending = st.session_state.pop("cookie_set_pending", None)
    if pending:
        st.html(cookie_script(pending, seconds_left(pending), _is_https()), unsafe_allow_javascript=True)
    if st.session_state.pop("cookie_clear_pending", False):
        st.html(cookie_script(None, 0, _is_https()), unsafe_allow_javascript=True)


def init_session() -> None:
    """Dipanggil app.py pada setiap run sebelum navigasi dibangun."""
    _restore_from_cookie()
    _enforce_expiry()
    _flush_cookie_ops()


def _user_label(user: dict) -> str:
    name = user.get('full_name') or user['username']
    role = user.get('role_label') or ROLE_LABELS.get(user['role'], user['role'])
    return name if name == role else f"{name} · {role}"


def render_page_login() -> None:
    """Halaman login sistem DSS."""
    st.subheader("Login Sistem")
    st.write("Silakan masuk menggunakan akun terdaftar untuk mengakses fitur sistem keputusan.")

    user = current_user()
    if user:
        st.success(f"Anda sudah login sebagai **{_user_label(user)}**.")
        if st.button("Logout", type="secondary"):
            render_page_logout()
        return
    if st.session_state.get("session_expired"):
        st.info("Sesi Anda telah berakhir. Silakan login kembali.")

    col1, col2 = st.columns([1, 1])
    with col1:
        with st.form("page_login_form", clear_on_submit=False):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login", type="primary", use_container_width=True)

        if submitted:
            if not username or not password:
                st.warning("Username dan password tidak boleh kosong.")
                return
            try:
                res = login(username, password)
            except ApiError as e:
                st.error(str(e))
            else:
                _set_session(res["access_token"], res["user"], remember=True)
                st.success(f"Login berhasil! Selamat datang, {res['user'].get('full_name') or res['user']['username']}.")
                st.rerun()


def render_page_account() -> None:
    """Halaman profil dan status akun pengguna saat ini."""
    st.subheader("Profil Akun")
    user = current_user()
    if not user:
        st.info("Anda belum login. Silakan buka menu Login di navigasi Akun.")
        return

    st.markdown(
        f"""
        **Username:** `{user.get('username')}`  
        **Nama Lengkap:** {user.get('full_name') or '-'}  
        **Peran (Role):** `{user.get('role_label') or ROLE_LABELS.get(user.get('role'), user.get('role'))}`  
        """
    )
    perms = user.get("permissions") or []
    if perms:
        with st.expander("Hak Akses (Permissions)", expanded=False):
            st.write(", ".join(f"`{p}`" for p in perms))
    st.caption(f"Sesi berakhir otomatis dalam ± {seconds_left(st.session_state.get('auth_token')) // 60} menit.")

    st.markdown("---")
    if st.button("Logout", type="secondary"):
        render_page_logout()


def render_page_logout() -> None:
    """Prosedur logout: membersihkan token, user session, dan cookie sesi lalu me-rerun aplikasi."""
    _end_session(expired=False)
    st.success("Berhasil logout.")
    st.rerun()


def render_auth_panel() -> None:
    """Komponen kontrol akun mandiri (popover Login / Logout) untuk disematkan di container."""
    user = current_user()
    label = _user_label(user) if user else "Akun · Login"
    with st.popover(label, use_container_width=True):
        if user:
            # Badge satu baris (lebih ringkas dari st.success); teks panjang dipotong dengan elipsis, utuh di tooltip.
            st.markdown(
                "<div title='Login sebagai {t}' style='padding:6px 10px;border-radius:8px;font-size:0.85rem;"
                "line-height:1.3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"
                "background:rgba(33,195,84,0.15);color:inherit;margin-bottom:8px;'>"
                "<span style='color:rgb(33,195,84);'>&#10003;</span> Login: <b>{t}</b></div>".format(
                    t=html.escape(_user_label(user))),
                unsafe_allow_html=True,
            )
            if st.button("Logout", use_container_width=True):
                _end_session(expired=False)
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
                _set_session(res["access_token"], res["user"], remember=True)
                st.rerun()


def processing_allowed() -> bool:
    """Memeriksa hak mengunggah dan mengolah temuan; bila tidak ada, tampilkan cara memperolehnya."""
    if can("dss.save_run"):
        return True
    if current_user() is None:
        st.info("Mengunggah laporan, penilaian, dan korelasi memerlukan login sebagai Analis Keamanan, Manajer "
                f"Keamanan, atau Administrator. Silakan login melalui {LOGIN_HINT}.")
    else:
        st.info("Role Anda hanya dapat melihat hasil. Mengunggah laporan, penilaian, dan korelasi memerlukan role "
                "Analis Keamanan, Manajer Keamanan, atau Administrator.")
    return False


def require_login(message: str = f"Halaman ini memerlukan login. Silakan login melalui {LOGIN_HINT}.") -> bool:
    if current_user() is None:
        st.info(message)
        return False
    return True
