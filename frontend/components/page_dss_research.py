# frontend/components/page_dss_research.py
"""
Halaman riset DSS (mode dev): sensitivitas bobot & escalation rate, perbandingan metode, dan evaluasi
terhadap ranking pakar. Seluruh angka berasal dari data sesi yang dipilih; tidak ada nilai contoh.
"""
import io

import pandas as pd
import plotly.express as px
import streamlit as st

from frontend.components.auth_panel import can
from frontend.components.tab_hybrid import HYBRID_LABEL, batch_label
from frontend.utils import api_client
from frontend.utils.api_client import ApiError


def _method_comparison(batch_id: str, methods: list[str]):
    orders = {}
    for m in methods:
        res = api_client.dss_rank(batch_id, method=m, persist=False)
        orders[m] = [it["key_id"] for it in res["items"]]
    from scipy.stats import kendalltau, spearmanr
    rows = []
    for i, a in enumerate(methods):
        for b in methods[i + 1:]:
            pos = {k: n for n, k in enumerate(orders[b])}
            ra, rb = list(range(len(orders[a]))), [pos[k] for k in orders[a]]
            rho = spearmanr(ra, rb)[0] if len(ra) > 1 else None
            tau = kendalltau(ra, rb)[0] if len(ra) > 1 else None
            rows.append({"Metode A": a, "Metode B": b, "Spearman ρ": rho, "Kendall τ": tau,
                         "Peringkat 1 sama": orders[a][:1] == orders[b][:1]})
    return pd.DataFrame(rows), orders


def render_page_dss_research():
    st.subheader("Riset DSS: Sensitivitas & Evaluasi")
    st.caption("Ukuran sampel (jumlah alternatif) selalu ditampilkan; laporkan bersama setiap koefisien korelasi.")
    try:
        batches = api_client.list_batches(HYBRID_LABEL)
        cfg = api_client.dss_config()
    except ApiError as e:
        st.error(str(e))
        return
    if not batches:
        st.info("Belum ada session Korelasi Hybrid.")
        return
    by_id = {b["batch_id"]: b for b in batches}
    batch_id = st.selectbox("Session:", list(by_id), format_func=lambda b: batch_label(by_id[b]))
    method = st.selectbox("Metode:", cfg["available_methods"], index=cfg["available_methods"].index(cfg["method"]))

    tab_w, tab_er, tab_m, tab_e = st.tabs(["Sensitivitas Bobot", "Sensitivitas ER", "Perbandingan Metode",
                                           "Evaluasi vs Pakar"])
    with tab_w:
        k = st.number_input("k (anggota peringkat teratas yang dibandingkan)", 1, 50, 10)
        try:
            sens = api_client.dss_sensitivity(batch_id, method, k=int(k))
        except ApiError as e:
            st.error(str(e))
        else:
            df = pd.DataFrame(sens["variants"])
            st.caption(f"n alternatif = {sens['n_alternatives']}; variasi bobot satu kriteria ±10/20/30%, "
                       "bobot lain diskalakan proporsional.")
            fig = px.line(df, x="delta", y="spearman_rho", color="criterion", markers=True,
                          labels={"delta": "Perubahan bobot", "spearman_rho": "Spearman ρ terhadap baseline",
                                  "criterion": "Kriteria"})
            fig.update_layout(height=380, xaxis_tickformat=".0%")
            st.plotly_chart(fig, width="stretch")
            st.dataframe(df.drop(columns=["weights"]), hide_index=True, width="stretch")
            st.download_button("Download CSV", df.to_csv(index=False), f"Sensitivitas_Bobot_{batch_id}_{method}.csv")
    with tab_er:
        rates_txt = st.text_input("Daftar escalation rate (pisahkan koma)", "0.00, 0.05, 0.10, 0.15, 0.20, 0.25")
        try:
            rates = [float(x) for x in rates_txt.split(",") if x.strip()]
            er = api_client.dss_er_sensitivity(batch_id, rates, method)
        except (ValueError, ApiError) as e:
            st.error(str(e))
        else:
            df = pd.DataFrame(er["variants"])
            st.caption(f"Baseline ER = {er['baseline_rate']}; n alternatif = {er['n_alternatives']}. "
                       "Bila seluruh pasangan berstatus True Positive, eskalasi bersifat monoton sehingga urutan "
                       "skor hybrid tidak berubah.")
            st.dataframe(df, hide_index=True, width="stretch")
            st.download_button("Download CSV", df.to_csv(index=False), f"Sensitivitas_ER_{batch_id}_{method}.csv")
    with tab_m:
        try:
            comp, orders = _method_comparison(batch_id, cfg["available_methods"])
        except ApiError as e:
            st.error(str(e))
        else:
            st.dataframe(comp, hide_index=True, width="stretch")
            st.dataframe(pd.DataFrame(orders).head(20).rename_axis("Peringkat").reset_index()
                         .assign(Peringkat=lambda d: d["Peringkat"] + 1), hide_index=True, width="stretch")
    with tab_e:
        st.write("Upload ranking pakar berformat CSV dengan kolom `key_id` (Pair ID) terurut dari prioritas "
                 "tertinggi. Evaluasi memakai run DSS tersimpan agar parameternya dapat direproduksi.")
        if not can("research.evaluate"):
            st.info("Evaluasi memerlukan login dengan role Analis Keamanan, Manajer Keamanan, atau Administrator.")
        else:
            runs = api_client.dss_runs(batch_id)
            if not runs:
                st.info("Belum ada run tersimpan untuk session ini. Buka halaman Prioritas Perbaikan dalam keadaan login agar run tersimpan.")
            else:
                run_id = st.selectbox("Run DSS:", [r["run_id"] for r in runs],
                                      format_func=lambda r: next(f"{x['created_at']} · {x['method']} · {x['weighting_source']}"
                                                                 for x in runs if x["run_id"] == r))
                up = st.file_uploader("Ranking pakar (.csv)", type=["csv"])
                k_eval = st.number_input("k untuk Precision@k", 1, 50, 10, key="k_eval")
                if up is not None:
                    try:
                        expert = pd.read_csv(io.BytesIO(up.getvalue()))["key_id"].astype(str).tolist()
                        ev = api_client.dss_evaluate(run_id, expert, int(k_eval))
                    except (KeyError, ApiError) as e:
                        st.error(f"Evaluasi gagal: {e}")
                    else:
                        st.dataframe(pd.DataFrame([
                            {"Pembanding": "DSS vs pakar", **ev["dss_vs_expert"]},
                            {"Pembanding": "Urutan skor saja vs pakar", **ev["score_only_vs_expert"]},
                        ]).drop(columns=["ignored_items"]), hide_index=True, width="stretch")
                        st.caption(ev["note"] + f" n = {ev['n_alternatives']}.")
                        ignored = ev["dss_vs_expert"]["ignored_items"]
                        if ignored:
                            st.warning(f"{len(ignored)} item hanya ada di salah satu ranking dan diabaikan.")
