# frontend/components/page_dss_research.py
"""
Halaman riset DSS (mode dev): sensitivitas bobot & escalation rate, serta perbandingan metode.
Seluruh angka berasal dari data sesi yang dipilih; tidak ada nilai contoh.
"""
import pandas as pd
import plotly.express as px
import streamlit as st

from frontend.components.tab_hybrid import batch_label
from frontend.utils import api_client
from frontend.utils.api_client import ApiError


def _method_comparison(batch_id: str, methods: list[str]):
    orders = {}
    for m in methods:
        res = api_client.dss_rank(batch_id, method=m, persist=False)
        orders[m] = [it["key_id"] for it in res["items"]]
    # Pembanding normalisasi: TOPSIS dengan normalisasi vektor klasik di samping normalisasi operasional (min-max).
    if "TOPSIS" in methods:
        res = api_client.dss_rank(batch_id, method="TOPSIS", persist=False, normalization="vector")
        orders["TOPSIS (vektor)"] = [it["key_id"] for it in res["items"]]
    methods = list(orders)
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
        batches = api_client.list_dss_batches()
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

    tab_w, tab_er, tab_m = st.tabs(["Sensitivitas Bobot", "Sensitivitas ER", "Perbandingan Metode"])
    with tab_w:
        k = st.number_input("k (anggota peringkat teratas yang dibandingkan)", 1, 50, 10)
        try:
            sens = api_client.dss_sensitivity(batch_id, method, k=int(k))
        except ApiError as e:
            st.error(str(e))
        else:
            df = pd.DataFrame(sens["variants"])
            st.caption(f"n alternatif = {sens['n_alternatives']}; variasi bobot satu kriteria ±10/20/30%, "
                       "bobot lain diskalakan proporsional. Kolom tanpa awalan membandingkan urutan akhir "
                       "(kelas prioritas, lalu MCDM di dalam kelas); kolom `mcdm_` membandingkan urutan MCDM saja.")
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
                       "Eskalasi hanya mengubah skor isu yang terdeteksi kedua pemindai dan dapat memindahkannya ke "
                       "kelas keparahan lain. Kolom tanpa awalan membandingkan urutan akhir; kolom `mcdm_` "
                       "membandingkan urutan MCDM saja.")
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
