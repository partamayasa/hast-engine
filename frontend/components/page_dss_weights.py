# frontend/components/page_dss_weights.py
"""Halaman Pengaturan Prioritas: aturan P1-P4, tenggat per prioritas, serta (lanjutan) bobot urutan, metode, dan AHP."""
import itertools

import pandas as pd
import streamlit as st

from frontend.components.auth_panel import can
from frontend.utils import api_client
from frontend.utils.api_client import ApiError

# Skala Saaty ditampilkan sebagai "A vs B": nilai < 1 berarti B lebih penting.
SAATY = [1 / 9, 1 / 7, 1 / 5, 1 / 3, 1, 3, 5, 7, 9]
SAATY_LABEL = {1 / 9: "1/9", 1 / 7: "1/7", 1 / 5: "1/5", 1 / 3: "1/3", 1: "1 (sama penting)", 3: "3", 5: "5", 7: "7", 9: "9"}


def _ahp_section(cfg: dict):
    st.markdown("##### Menetapkan bobot dengan AHP (perbandingan berpasangan)")
    st.write("Isi perbandingan berpasangan dengan skala Saaty 1–9. Nilai > 1 berarti kriteria di kiri **lebih penting** "
             "daripada kriteria di kanan; nilai < 1 berarti sebaliknya. Bobot disimpan hanya bila CR ≤ 0,10.")
    labels = {c["key"]: f"{c.get('code', '')} {c['label']}".strip() for c in cfg["criteria"]}
    default_keys = [c["key"] for c in cfg["criteria"] if c.get("enabled", True)]
    keys = st.multiselect("Kriteria yang dibandingkan:", list(labels), default=default_keys,
                          format_func=lambda k: labels[k])
    if len(keys) < 2:
        st.info("Pilih minimal dua kriteria.")
        return
    prev = cfg.get("ahp") or {}
    prev_m = prev.get("matrix") if prev.get("criteria") == keys else None

    n = len(keys)
    matrix = [[1.0] * n for _ in range(n)]
    for i, j in itertools.combinations(range(n), 2):
        start = prev_m[i][j] if prev_m else 1
        start = min(SAATY, key=lambda s: abs(s - start))
        v = st.select_slider(f"{labels[keys[i]]}  vs  {labels[keys[j]]}", options=SAATY, value=start,
                             format_func=lambda s: SAATY_LABEL[s], key=f"ahp_{keys[i]}_{keys[j]}")
        matrix[i][j], matrix[j][i] = float(v), 1.0 / float(v)

    try:
        res = api_client.dss_ahp(keys, matrix)
    except ApiError as e:
        st.error(str(e))
        return
    c1, c2, c3 = st.columns(3)
    c1.metric("λ maks", f"{res['lambda_max']:.4f}")
    c2.metric("CI", f"{res['ci']:.4f}")
    c3.metric("CR", f"{res['cr']:.4f}", delta="konsisten" if res["is_consistent"] else "tidak konsisten",
              delta_color="normal" if res["is_consistent"] else "inverse")
    st.dataframe(pd.DataFrame([{"Kriteria": labels[k], "Bobot AHP": w} for k, w in res["weights"].items()]),
                 hide_index=True, width="stretch")
    source = st.text_input("Sumber penilaian (dicatat bersama bobot):", value=prev.get("source") or "",
                           placeholder="Mis. rata-rata geometrik penilaian 3 pakar, 2026-11-20")
    if st.button("Simpan Bobot AHP ke Konfigurasi", type="primary", disabled=not (can("settings.manage") and res["is_consistent"])):
        try:
            api_client.dss_ahp(keys, matrix, save=True, source=source or None)
        except ApiError as e:
            st.error(str(e))
        else:
            st.success("Bobot AHP tersimpan. Sumber bobot konfigurasi kini 'ahp'.")
            st.cache_data.clear()
    if not res["is_consistent"]:
        st.warning("CR melebihi 0,10: tinjau ulang perbandingan yang saling bertentangan sebelum menyimpan.")


META_KEYS = ("available_methods", "actions", "statuses", "priorities", "business_impact_levels", "effort_levels",
             "_source_file")
PRIORITY_ACTIONS = [("P1", "REMEDIATE_NOW"), ("P2", "REMEDIATE_SCHEDULED"), ("P3", "PLAN"), ("P4", "REVIEW_OR_ACCEPT")]


def _save(new_cfg: dict, ok_msg: str):
    try:
        api_client.dss_update_config({k: v for k, v in new_cfg.items() if k not in META_KEYS})
    except ApiError as e:
        st.error(f"Settings ditolak: {e}")
    else:
        st.success(ok_msg)
        st.cache_data.clear()


def _policy_section(cfg: dict):
    st.markdown("#### Aturan prioritas")
    st.write("Prioritas ditentukan oleh aturan berikut, diperiksa dari atas; aturan pertama yang cocok dipakai.")
    st.dataframe(pd.DataFrame([{
        "Prioritas": cfg["priorities"].get(r.get("priority"), r.get("priority") or ""),
        "Kondisi": r.get("text") or str(r.get("when")),
        "Tindakan": cfg["actions"].get(r["action"], r["action"]),
    } for r in cfg["recommendation_rules"]]), hide_index=True, width="stretch")
    st.caption("Dampak bisnis setiap issue diisi analis di halaman Prioritas Perbaikan; nilai Tinggi atau Sangat tinggi "
               "(4–5) dapat menaikkan issue HIGH ke P1 dan issue MEDIUM ke P2.")

    st.markdown("#### Due date penanganan per prioritas")
    st.caption("Kebijakan organisasi Anda (jumlah hari sejak issue pertama kali direkomendasikan). "
               "Nonaktifkan bila suatu prioritas tidak memiliki due date.")
    sla = {}
    cols = st.columns(4)
    for col, (prio, action) in zip(cols, PRIORITY_ACTIONS):
        days = cfg["sla_days"].get(action)
        with col:
            use = st.checkbox(f"{cfg['priorities'][prio]}", value=days is not None, key=f"sla_on_{action}")
            v = st.number_input("Hari", min_value=0, max_value=3650, value=days if days is not None else 30, step=1,
                                key=f"sla_{action}", disabled=not use)
            sla[action] = int(v) if use else None
    if st.button("Simpan due date", type="primary", disabled=not can("settings.manage")):
        _save({**cfg, "sla_days": sla}, "Due date tersimpan. Berlaku untuk issue baru dan issue yang belum memiliki due date.")


def _advanced_section(cfg: dict):
    st.write("Bobot berikut hanya menentukan **urutan issue di dalam prioritas yang sama** (metode "
             f"{cfg['method']}). Prioritas P1–P4 tetap ditentukan oleh aturan di atas.")
    methods = cfg.get("available_methods", ["TOPSIS", "SAW", "WP"])
    method = st.selectbox("Metode pengurutan:", methods, index=methods.index(cfg["method"]))
    crit_df = pd.DataFrame([{"key": c["key"], "Faktor": c["label"], "Arah": c["direction"],
                             "Bobot": float(c["weight"]), "Aktif": bool(c.get("enabled", True))} for c in cfg["criteria"]])
    edited = st.data_editor(crit_df, hide_index=True, width="stretch", key="crit_editor",
                            column_config={"key": None,
                                           "Faktor": st.column_config.TextColumn(disabled=True),
                                           "Arah": st.column_config.SelectboxColumn(options=["benefit", "cost"]),
                                           "Bobot": st.column_config.NumberColumn(min_value=0.0, max_value=1.0, step=0.01),
                                           "Aktif": st.column_config.CheckboxColumn()})
    if st.button("Simpan bobot", disabled=not can("settings.manage")):
        new_cfg = {**cfg, "method": method, "criteria": [dict(c) for c in cfg["criteria"]]}
        changed = False
        for c in new_cfg["criteria"]:
            r = edited[edited["key"] == c["key"]].iloc[0]
            changed |= abs(float(r["Bobot"]) - float(c["weight"])) > 1e-9
            c["weight"], c["enabled"], c["direction"] = float(r["Bobot"]), bool(r["Aktif"]), r["Arah"]
        if changed:
            new_cfg["weighting_source"] = "manual"
        _save(new_cfg, "Bobot tersimpan.")
    st.markdown("---")
    _ahp_section(cfg)


def render_page_dss_weights():
    st.subheader("Priority Settings")
    if not can("settings.manage"):
        st.info("Settings dapat dilihat siapa saja; perubahan hanya dapat disimpan oleh **Manajer Keamanan** atau **Administrator**.")
    try:
        cfg = api_client.dss_config()
    except ApiError as e:
        st.error(str(e))
        return
    _policy_section(cfg)
    st.markdown("---")
    with st.expander("Advanced settings: bobot urutan di dalam prioritas", expanded=False):
        st.caption(f"Sumber bobot saat ini: **{cfg.get('weighting_source')}**"
                   + (f" · AHP: {cfg['ahp'].get('source')} (CR {cfg['ahp'].get('consistency_ratio')})"
                      if (cfg.get("ahp") or {}).get("matrix") else ""))
        if cfg.get("_note"):
            st.caption(cfg["_note"])
        _advanced_section(cfg)
