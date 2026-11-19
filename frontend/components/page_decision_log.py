# frontend/components/page_decision_log.py
"""Riwayat Keputusan: ringkasan baca-saja atas tindak lanjut setiap isu lintas sesi pemindaian, beserta jejak audit."""
import pandas as pd
import streamlit as st

from frontend.components.auth_panel import can
from frontend.utils import api_client
from frontend.utils.api_client import ApiError


def render_page_decision_log():
    st.subheader("Decision History")
    st.caption("Ringkasan tindak lanjut semua issue dari seluruh scan. Perubahan dilakukan di halaman "
               "**Prioritas Perbaikan**; halaman ini untuk memantau dan mengaudit.")
    try:
        cfg = api_client.dss_config()
        decisions = api_client.list_decisions()
        agreement = api_client.decision_agreement()
    except ApiError as e:
        st.error(f"Gagal memuat history: {e}")
        return
    statuses = cfg["statuses"]
    # Hanya keputusan tingkat isu (record tingkat pasangan dari pengujian awal v2 tidak memiliki judul).
    decisions = [d for d in decisions if d.get("title")]
    if not decisions:
        st.info("Belum ada keputusan tercatat. Buka **Prioritas Perbaikan** dalam keadaan login untuk mulai mencatat.")
        return

    open_n = sum(1 for d in decisions if not d["is_closed"])
    m = st.columns(4)
    m[0].metric("Issue tercatat", len(decisions))
    m[1].metric("Masih terbuka", open_n)
    m[2].metric("Overdue", sum(1 for d in decisions if d["is_overdue"]))
    m[3].metric("Sesuai rekomendasi", "—" if agreement["rate"] is None else f"{agreement['rate'] * 100:.0f}%",
                help="Dari issue yang sudah ditindaklanjuti analis, porsi yang tetap memakai prioritas "
                     "rekomendasi sistem (tidak diubah).")

    status_opt = st.multiselect("Status", list(statuses), default=[], placeholder="Semua status",
                                format_func=lambda s: statuses[s])
    rows = [d for d in decisions if not status_opt or d["status"] in status_opt]
    df = pd.DataFrame([{
        "Issue": d["title"], "CWE": d["cwe_id"], "Prioritas": d["priority_label"] or "—",
        "Status": d["status_label"], "Penanggung jawab": d["owner"] or "—",
        "Due date": d["sla_due_date"] or "—", "Overdue": "Ya" if d["is_overdue"] else "",
        "Dampak bisnis": d["business_impact_label"] or "Belum dinilai",
        "Upaya": d["effort_label"] or "—", "Catatan": d["reason"] or "",
        "Diputuskan oleh": d["decided_by"] or "—", "Scan terakhir": d["last_batch_id"],
    } for d in rows])
    st.dataframe(df, hide_index=True, width="stretch")

    if can("report.export"):
        try:
            st.download_button("Download history (.xlsx)", api_client.export_decisions_xlsx(),
                               file_name="Riwayat_Keputusan.xlsx",
                               mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        except ApiError:
            pass

    st.markdown("#### Audit trail per issue")
    by_key = {d["decision_key"]: d for d in rows}
    if not by_key:
        return
    key = st.selectbox("Pilih issue:", list(by_key), format_func=lambda k: f"{by_key[k]['title']} ({by_key[k]['cwe_id']})")
    try:
        events = api_client.decision_events(key)
    except ApiError as e:
        st.error(str(e))
        return
    st.dataframe(pd.DataFrame([{
        "Waktu": e["created_at"][:16], "Oleh": e["actor"] or "sistem",
        "Peristiwa": {"RECOMMENDED": "Rekomendasi sistem", "DECIDED": "Keputusan", "UPDATED": "Perubahan data"}
        .get(e["event_type"], e["event_type"]),
        "Status": statuses.get(e["to_status"] or "", e["to_status"] or ""),
        "Catatan": e["reason"] or "",
        "Konteks model saat itu": " ".join(filter(None, [
            (e.get("model_context") or {}).get("score_origin"),
            (e.get("model_context") or {}).get("model_reason"),
            " ".join((e.get("model_context") or {}).get("review_notes") or [])])),
    } for e in reversed(events)]), hide_index=True, width="stretch")
