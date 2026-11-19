# frontend/components/page_users.py
"""Halaman Pengguna (Administrator): daftar akun, ubah peran/status lewat dropdown, tambah akun, dan katalog peran."""
import pandas as pd
import streamlit as st

from frontend.components.auth_panel import can, current_user
from frontend.utils import api_client
from frontend.utils.api_client import ApiError


@st.cache_data(ttl=300)
def _catalog() -> dict:
    return api_client.list_roles()


def _role_table(catalog: dict):
    perms = catalog["permissions"]
    rows = []
    for r in catalog["roles"]:
        rows.append({"Role": r["label"], "Untuk": r["description"],
                     "Hak akses": "; ".join(perms[p] for p in r["permissions"])})
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def render_page_users():
    st.subheader("User Management")
    try:
        catalog = _catalog()
    except ApiError as e:
        st.error(str(e))
        return
    if not can("users.manage"):
        st.info("Halaman ini hanya untuk role **Administrator**. Berikut daftar role yang tersedia:")
        _role_table(catalog)
        return

    label_of = {r["key"]: r["label"] for r in catalog["roles"]}
    key_of = {v: k for k, v in label_of.items()}
    try:
        users = api_client.list_users()
    except ApiError as e:
        st.error(str(e))
        return

    st.markdown("#### Daftar user")
    st.caption("Ubah **Role**, **Nama lengkap**, atau **Aktif** langsung pada tabel, lalu klik Simpan perubahan.")
    view = pd.DataFrame([{"Username": u["username"], "Nama lengkap": u["full_name"] or "",
                          "Role": label_of.get(u["role"], u["role"]), "Aktif": bool(u["is_active"])} for u in users])
    edited = st.data_editor(
        view, hide_index=True, width="stretch", key="users_editor", num_rows="fixed",
        column_config={
            "Username": st.column_config.TextColumn(disabled=True),
            "Nama lengkap": st.column_config.TextColumn(max_chars=128),
            "Role": st.column_config.SelectboxColumn(options=list(label_of.values()), required=True),
            "Aktif": st.column_config.CheckboxColumn(),
        },
    )
    if st.button("Simpan perubahan", type="primary"):
        original = view.set_index("Username")
        ok, errors = 0, []
        for _, row in edited.iterrows():
            name = row["Username"]
            before = original.loc[name]
            changes = {}
            if row["Role"] != before["Role"]:
                changes["role"] = key_of[row["Role"]]
            if bool(row["Aktif"]) != bool(before["Aktif"]):
                changes["is_active"] = bool(row["Aktif"])
            if (row["Nama lengkap"] or "") != (before["Nama lengkap"] or ""):
                changes["full_name"] = row["Nama lengkap"] or ""
            if not changes:
                continue
            try:
                api_client.update_user(name, changes)
                ok += 1
            except ApiError as e:
                errors.append(f"{name}: {e}")
        if ok:
            st.success(f"{ok} user diperbarui. Perubahan role berlaku saat user tersebut login kembali.")
        for e in errors:
            st.error(e)
        if not ok and not errors:
            st.info("Tidak ada perubahan.")

    st.markdown("#### Tambah user")
    with st.form("new_user", clear_on_submit=True):
        c1, c2 = st.columns(2)
        username = c1.text_input("Username (huruf, angka, . _ -)")
        full_name = c2.text_input("Nama lengkap (opsional)")
        c3, c4 = st.columns(2)
        role = c3.selectbox("Role", list(label_of), index=list(label_of).index("analyst"),
                            format_func=lambda k: label_of[k])
        password = c4.text_input("Password awal (min. 8 karakter)", type="password")
        if st.form_submit_button("Buat akun"):
            try:
                api_client.create_user(username, password, role, full_name or None)
            except ApiError as e:
                st.error(str(e))
            else:
                st.success(f"Akun {username} ({label_of[role]}) dibuat.")

    with st.expander("Penjelasan role dan hak akses", expanded=False):
        _role_table(catalog)
    me = current_user() or {}
    st.caption(f"Anda login sebagai {me.get('username')}. Sistem selalu mempertahankan minimal satu Administrator "
               "aktif, dan Anda tidak dapat menonaktifkan akun Anda sendiri.")
