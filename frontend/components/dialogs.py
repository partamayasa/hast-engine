# frontend/components/dialogs.py
import streamlit as st
from frontend.components.auth_panel import can
from frontend.utils.api_client import ApiError, clear_history, delete_batch
from frontend.utils.formatters import prefix_scanner


def _after_change(batch_id=None):
    try:
        from frontend.components.history import clear_shap_cache, load_cached_scan_history
        clear_shap_cache(batch_id)
        load_cached_scan_history.clear()
    except Exception:
        pass


def _login_required_notice():
    st.info("Penghapusan history hanya dapat dilakukan Manajer Keamanan atau Administrator yang sudah login.")


@st.dialog("Konfirmasi Hapus Session")
def confirm_delete_batch_dialog(batch_id):
    st.warning(f"Apakah anda yakin ingin menghapus history session **{batch_id}**?")
    if not can("history.delete"):
        _login_required_notice()
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        if st.button("Ya, Hapus Session", type="primary", use_container_width=True, key=f"confirm_del_{batch_id}",
                     disabled=not can("history.delete")):
            try:
                delete_batch(batch_id)
            except ApiError as e:
                st.error(f"Gagal menghapus session: {e}")
                st.stop()
            _after_change(batch_id)
            st.toast(f"Session {batch_id} berhasil dihapus dari database!", icon=None)
            st.rerun()
    with col_c2:
        if st.button("Batal", use_container_width=True, key=f"cancel_del_{batch_id}"):
            st.rerun()


@st.dialog("Konfirmasi Hapus Seluruh History")
def confirm_clear_all_dialog(scanner_type):
    st.error(f"Apakah anda yakin ingin menghapus seluruh history **{scanner_type}**?")
    if not can("history.delete"):
        _login_required_notice()
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        if st.button("Ya, Hapus Semua", type="primary", use_container_width=True,
                     key=f"confirm_clear_{prefix_scanner(scanner_type)}",
                     disabled=not can("history.delete")):
            try:
                clear_history(scanner_type)
            except ApiError as e:
                st.error(f"Gagal menghapus history: {e}")
                st.stop()
            _after_change()
            st.toast(f"Seluruh histori {scanner_type} telah dibersihkan!", icon=None)
            st.rerun()
    with col_c2:
        if st.button("Batal", use_container_width=True, key=f"cancel_clear_{prefix_scanner(scanner_type)}"):
            st.rerun()
