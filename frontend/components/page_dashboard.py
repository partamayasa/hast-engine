# frontend/components/page_dashboard.py
"""
Dasbor — ringkasan kondisi keamanan dalam satu layar.

Menjawab pertanyaan harian manajer dan analis: berapa isu yang masih terbuka, berapa yang mendesak (P1),
apa yang lewat atau mendekati tenggat, siapa yang memegang beban kerja terbanyak, kelemahan (CWE) apa yang
paling sering muncul, dan bagaimana sebaran keparahan pada pemindaian terakhir. Seluruh angka berasal dari
endpoint `/api/v1/dashboard`; halaman ini tidak menghitung skor atau prioritas sendiri.
"""
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from frontend.utils import api_client
from frontend.utils.api_client import ApiError

# Slot kategorikal berurutan tetap (blue, orange, aqua) — tiga slot pertama lolos validasi CVD untuk semua pasangan.
SERIES_COLORS = ("#2a78d6", "#eb6834", "#1baf7a")
SINGLE_SERIES_COLOR = SERIES_COLORS[0]
# Warna mengikuti entitas, bukan urutan: jenis pemindaian dan kelompok status selalu memakai slot yang sama.
SCANNER_COLORS = {"SonarQube (SAST)": SERIES_COLORS[0], "OWASP ZAP (DAST)": SERIES_COLORS[1],
                  "Pengujian Korelasi Hybrid": SERIES_COLORS[2]}
SCANNER_SHORT = {"SonarQube (SAST)": "SAST", "OWASP ZAP (DAST)": "DAST", "Pengujian Korelasi Hybrid": "Hybrid"}
# Status terbuka dikelompokkan menjadi tiga agar warna tetap terbedakan; status tertutup tampil sebagai angka kunci.
OPEN_STATUS_GROUPS = {"OPEN": "Belum ditangani", "IN_PROGRESS": "Sedang dikerjakan", "DEFERRED": "Ditunda"}
OPEN_GROUP_COLORS = {"Belum ditangani": SERIES_COLORS[1], "Sedang dikerjakan": SERIES_COLORS[0],
                     "Ditunda": SERIES_COLORS[2]}
PRIORITY_ROWS = ("P1 · Segera", "P2 · Terjadwal", "P3 · Direncanakan", "P4 · Pantau")
SEVERITY_LABELS = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "NONE": "None"}


def _layout(fig: go.Figure, height: int, legend: bool) -> go.Figure:
    """Menerapkan gaya bersama (tanpa garis sumbu, legenda di atas bila ada >= 2 seri); grid diatur per grafik."""
    fig.update_layout(
        height=height, margin=dict(l=8, r=24, t=36 if legend else 8, b=8), bargap=0.35, bargroupgap=0.08,
        showlegend=legend, hoverlabel=dict(namelength=-1),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, title_text=""),
    )
    fig.update_xaxes(zeroline=False, showline=False, automargin=True)
    fig.update_yaxes(zeroline=False, showline=False, automargin=True)
    fig.update_traces(marker_line_width=0)
    return fig


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.0f}%"


def _render_kpis(k: dict):
    row1 = st.columns(4)
    row1[0].metric("Issue terbuka", k["open_issues"], help=f"Dari {k['total_issues']} issue yang tercatat di DSS.")
    row1[1].metric("P1 · Segera (terbuka)", k["p1_open"],
                   help="Issue terbuka dengan prioritas efektif P1 (rekomendasi sistem atau ketetapan analis).")
    row1[2].metric("Overdue", k["overdue"], help="Issue terbuka yang tanggal due date SLA-nya sudah lewat.")
    row1[3].metric(f"Due date ≤ {k['due_soon_days']} hari", k["due_soon"],
                   help="Issue terbuka yang belum overdue tetapi jatuh tempo dalam rentang ini.")
    row2 = st.columns(4)
    row2[0].metric("Sedang dikerjakan", k["in_progress"])
    row2[1].metric("Belum ditugaskan", k["unassigned_open"], help="Issue terbuka tanpa penanggung jawab.")
    row2[2].metric("Ditutup", f"{k['closed_issues']} ({_pct(k['closure_rate'])})",
                   help="Selesai diperbaiki, risiko diterima, atau false positive; persentase terhadap seluruh issue.")
    agree = k["agreement"]
    row2[3].metric("Sesuai rekomendasi", _pct(agree["rate"]),
                   help=f"Dari {agree['decided']} issue yang sudah ditindaklanjuti analis, {agree['agreed']} "
                        "memakai prioritas yang sama dengan rekomendasi sistem.")
    if k["needs_review_open"]:
        st.warning(f"{k['needs_review_open']} issue terbuka bertanda **Perlu diperiksa**: skor model sebaiknya "
                   "diverifikasi manual sebelum diputuskan (lihat tab *Asal skor* di Prioritas Perbaikan).")


def _render_priority_status(rows: list[dict]):
    st.markdown("**Issue terbuka per prioritas**")
    df = pd.DataFrame(rows)
    if df.empty:
        st.info("Belum ada issue terbuka.")
        return
    df = df[df["status"].isin(OPEN_STATUS_GROUPS)].copy()
    if df.empty:
        st.success("Semua issue sudah ditutup.")
        return
    df["group"] = df["status"].map(OPEN_STATUS_GROUPS)
    pivot = df.pivot_table(index="priority_label", columns="group", values="count", aggfunc="sum", fill_value=0)
    priorities = [p for p in PRIORITY_ROWS if p in pivot.index] + [p for p in pivot.index if p not in PRIORITY_ROWS]
    pivot = pivot.reindex(priorities)
    groups = [g for g in OPEN_STATUS_GROUPS.values() if g in pivot.columns]
    fig = go.Figure()
    for g in groups:
        fig.add_bar(y=pivot.index, x=pivot[g], name=g, orientation="h", marker_color=OPEN_GROUP_COLORS[g],
                    hovertemplate="%{y}<br>" + g + ": %{x}<extra></extra>")
    fig.update_layout(barmode="stack")
    fig.update_yaxes(autorange="reversed", showgrid=False)
    fig.update_xaxes(showgrid=True, dtick=1, title_text="Jumlah issue")
    # Legenda selalu tampil karena warna di grafik ini menandai status, bukan hanya nama seri.
    st.plotly_chart(_layout(fig, 260, legend=True), width="stretch")
    with st.expander("Lihat data"):
        st.dataframe(pivot.assign(Total=pivot.sum(axis=1)).rename_axis("Prioritas"), width="stretch")


def _render_latest_scans(scans: list[dict], severity_order: list[str]):
    st.markdown("**Sebaran severity pada scan terakhir**")
    if not scans:
        st.info("Belum ada scan history.")
        return
    labels = [SEVERITY_LABELS.get(s, s) for s in severity_order]
    order = list(SCANNER_COLORS)
    scans = sorted(scans, key=lambda s: order.index(s["scanner_type"]) if s["scanner_type"] in order else len(order))
    fig = go.Figure()
    for scan in scans:
        name = SCANNER_SHORT.get(scan["scanner_type"], scan["scanner_type"])
        fig.add_bar(x=labels, y=[scan["severity"].get(s, 0) for s in severity_order], name=name,
                    marker_color=SCANNER_COLORS.get(scan["scanner_type"], SINGLE_SERIES_COLOR),
                    hovertemplate=f"{name} · {scan['batch_id']}<br>" + "%{x}: %{y} temuan<extra></extra>")
    fig.update_layout(barmode="group")
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(showgrid=True, title_text="Jumlah temuan")
    st.plotly_chart(_layout(fig, 260, legend=len(scans) >= 2), width="stretch")
    with st.expander("Lihat data"):
        st.dataframe(pd.DataFrame([{
            "Jenis": SCANNER_SHORT.get(s["scanner_type"], s["scanner_type"]), "Session": s["batch_id"],
            "Waktu": s["timestamp"], "Temuan": s["count"], "Rata-rata skor": s["avg_score"],
            "Skor tertinggi": s["max_score"],
            **{SEVERITY_LABELS[sev]: s["severity"].get(sev, 0) for sev in severity_order},
        } for s in scans]), hide_index=True, width="stretch")


def _render_single_bar(title: str, df: pd.DataFrame, label_col: str, value_col: str, hover: str,
                       empty_text: str, table: pd.DataFrame | None = None):
    st.markdown(f"**{title}**")
    if df.empty:
        st.info(empty_text)
        return
    fig = go.Figure(go.Bar(y=df[label_col], x=df[value_col], orientation="h", marker_color=SINGLE_SERIES_COLOR,
                           text=df[value_col], textposition="outside", cliponaxis=False,
                           customdata=df.drop(columns=[label_col]).values, hovertemplate=hover + "<extra></extra>"))
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(showticklabels=False, showgrid=False)
    st.plotly_chart(_layout(fig, max(110, 34 * len(df) + 40), legend=False), width="stretch")
    with st.expander("Lihat data"):
        st.dataframe(table if table is not None else df, hide_index=True, width="stretch")


def _render_deadlines(rows: list[dict]):
    st.markdown("**Nearest due date**")
    if not rows:
        st.info("Tidak ada issue terbuka yang memiliki due date.")
        return

    def when(r):
        d = r["days_left"]
        if d < 0:
            return f"⚠ Lewat {-d} hari"
        return "Hari ini" if d == 0 else f"{d} hari lagi"

    st.dataframe(pd.DataFrame([{
        "Sisa waktu": when(r), "Issue": r["title"], "CWE": r["cwe_id"], "Prioritas": r["priority_label"],
        "Status": r["status_label"], "Penanggung jawab": r["owner"] or "—", "Due date": r["sla_due_date"],
    } for r in rows]), hide_index=True, width="stretch")


def _render_trend(trend: list[dict]):
    st.markdown("**Tren temuan High + Critical per scan session**")
    df = pd.DataFrame([{
        "scanner": SCANNER_SHORT.get(t["scanner_type"], t["scanner_type"]), "scanner_type": t["scanner_type"],
        "batch": t["batch_id"], "time": pd.to_datetime(t["timestamp"], errors="coerce"),
        "high_critical": t["severity"].get("HIGH", 0) + t["severity"].get("CRITICAL", 0), "total": t["count"],
    } for t in trend])
    if df.empty or df.groupby("scanner").size().max() < 2:
        st.caption("Tren muncul setelah ada minimal dua scan session untuk jenis yang sama.")
        return
    fig = go.Figure()
    for scanner_type, part in df.sort_values("time").groupby("scanner_type", sort=False):
        fig.add_scatter(x=part["time"], y=part["high_critical"], mode="lines+markers",
                        name=SCANNER_SHORT.get(scanner_type, scanner_type),
                        line=dict(width=2, color=SCANNER_COLORS.get(scanner_type, SINGLE_SERIES_COLOR)),
                        marker=dict(size=8), customdata=part[["batch", "total"]].values,
                        hovertemplate="%{customdata[0]}<br>High + Critical: %{y} dari %{customdata[1]} temuan"
                                      "<extra></extra>")
    fig.update_yaxes(showgrid=True, rangemode="tozero", title_text="Temuan High + Critical")
    fig.update_xaxes(showgrid=False)
    fig.update_layout(hovermode="x unified")
    st.plotly_chart(_layout(fig, 280, legend=df["scanner"].nunique() >= 2), width="stretch")


def render_page_dashboard():
    st.header("Dashboard")
    st.caption("Ringkasan issue keamanan, due date, dan hasil scan terakhir. Klik ikon pada grafik untuk "
               "memperbesar; buka *Lihat data* untuk angka lengkapnya.")
    try:
        data = api_client.dashboard_summary()
    except ApiError as e:
        st.error(f"Ringkasan dashboard tidak dapat dimuat: {e}")
        return

    kpis = data["kpis"]
    if kpis["total_issues"] == 0 and not data["latest_scans"]:
        st.info("Belum ada data. Upload laporan di halaman **1. SonarQube (SAST)** dan **2. OWASP ZAP (DAST)**, "
                "jalankan **3. Korelasi Hybrid**, lalu buka **Prioritas Perbaikan** untuk membentuk daftar issue.")
        return

    has_hybrid = any(SCANNER_SHORT.get(s["scanner_type"]) == "Hybrid" for s in data["latest_scans"])
    if kpis["total_issues"] == 0 and has_hybrid:
        # Issue baru tercatat saat Prioritas Perbaikan dibuka oleh role yang berhak menyimpan (pelaku tercatat).
        st.warning("Hasil **Korelasi Hybrid** sudah ada, tetapi issue-nya belum dicatat di DSS. Login dengan role "
                   "Analis Keamanan, Manajer Keamanan, atau Administrator, lalu buka halaman **Prioritas Perbaikan** "
                   "agar issue dan rekomendasinya tercatat dan angka di dashboard terisi.")

    _render_kpis(kpis)
    st.divider()

    left, right = st.columns(2)
    with left:
        _render_priority_status(data["priority_status"])
    with right:
        _render_latest_scans(data["latest_scans"], data["severity_order"])

    left, right = st.columns(2)
    with left:
        cwe = pd.DataFrame(data["top_cwe"], columns=["cwe_id", "open", "p1_open"])
        _render_single_bar("CWE dengan issue terbuka terbanyak", cwe, "cwe_id", "open",
                           "%{y}: %{x} issue terbuka<br>P1: %{customdata[1]}", "Belum ada issue terbuka.",
                           cwe.rename(columns={"cwe_id": "CWE", "open": "Issue terbuka", "p1_open": "P1 terbuka"}))
    with right:
        owners = pd.DataFrame(data["owner_load"], columns=["owner", "open", "p1_open", "overdue"])
        _render_single_bar("Beban kerja per penanggung jawab", owners, "owner", "open",
                           "%{y}: %{x} issue terbuka<br>P1: %{customdata[1]} · overdue: %{customdata[2]}",
                           "Belum ada issue terbuka.",
                           owners.rename(columns={"owner": "Penanggung jawab", "open": "Issue terbuka",
                                                  "p1_open": "P1 terbuka", "overdue": "Overdue"}))

    _render_deadlines(data["deadlines"])
    _render_trend(data["scan_trend"])
