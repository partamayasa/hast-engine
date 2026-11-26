# frontend/components/page_priority.py
"""
Prioritas Perbaikan — daftar kerja DSS.

Menjawab, untuk setiap isu: apa yang diperbaiki lebih dulu, mengapa, bagaimana caranya, di mana lokasinya,
siapa penanggung jawabnya, dan kapan tenggatnya. Setiap isu menggabungkan seluruh pasangan SAST-DAST dari satu
jenis alert OWASP ZAP + CWE. Keputusan (status, penanggung jawab, tenggat, dampak bisnis, upaya, perubahan
prioritas) dicatat langsung di halaman dan diaudit oleh backend. Detail teknis MCDM hanya tampil di mode riset (dev).
"""
import datetime
import html
import re

import pandas as pd
import streamlit as st

from frontend.components.auth_panel import LOGIN_HINT, can, current_user
from frontend.components.tab_hybrid import batch_label
from frontend.utils import api_client
from frontend.utils.api_client import ApiError

PRIORITY_STYLE = {
    "P1": ("#c0392b", "P1 · Segera"),
    "P2": ("#d35400", "P2 · Terjadwal"),
    "P3": ("#b7950b", "P3 · Direncanakan"),
    "P4": ("#7f8c8d", "P4 · Pantau"),
}
SOURCE_LABELS = {"hybrid": "SAST dan DAST", "sast": "SAST saja", "dast": "DAST saja"}
SEVERITY_COLOR = {"CRITICAL": "#8e44ad", "HIGH": "#c0392b", "MEDIUM": "#d68910", "LOW": "#2e86c1", "NONE": "#7f8c8d"}
# Skala 1-5 untuk dampak bisnis (C6) dan upaya perbaikan (C7); sama dengan backend/dss/recommender.py.
BI_OPTIONS = {5: "Sangat tinggi", 4: "Tinggi", 3: "Sedang", 2: "Rendah", 1: "Sangat rendah"}
EFFORT_OPTIONS = {1: "Sangat kecil (≤ 1 jam)", 2: "Kecil (≤ 1 hari)", 3: "Sedang (≤ 1 minggu)",
                  4: "Besar (≤ 1 bulan)", 5: "Sangat besar (> 1 bulan)"}
NOT_ASSESSED = "Belum dinilai"
PRIORITY_TO_ACTION = {"P1": "REMEDIATE_NOW", "P2": "REMEDIATE_SCHEDULED", "P3": "PLAN", "P4": "REVIEW_OR_ACCEPT"}
PROGRESS_STATUSES = ("OPEN", "IN_PROGRESS", "RESOLVED")


def _perms() -> dict:
    return {
        "triage": can("decision.triage"),
        "override": can("decision.override_priority"),
        "accept": can("decision.accept_risk"),
        "progress": can("decision.update_progress"),
    }


def _fmt_date(iso: str | None) -> str:
    if not iso:
        return "tanpa due date"
    try:
        return datetime.date.fromisoformat(iso).strftime("%d %b %Y")
    except ValueError:
        return iso


def _badge(priority: str) -> str:
    color, label = PRIORITY_STYLE.get(priority, ("#7f8c8d", priority))
    return (f"<span style='background:{color};color:white;padding:2px 10px;border-radius:12px;"
            f"font-weight:600;font-size:0.85rem'>{label}</span>")


REVIEW_BADGE = ("<span style='border:1px solid #b9770e;color:#b9770e;padding:1px 8px;border-radius:12px;"
                "font-size:0.8rem;font-weight:600'>Perlu diperiksa</span>")


def _token_df(tokens: list[dict], label: str) -> pd.DataFrame:
    return pd.DataFrame([{label: t["token"], "Pengaruh": f"{t['value']:+.2f}"} for t in tokens])


def _render_score_origin(item: dict):
    exp = item.get("score_explanation") or {}
    chain = exp.get("chain") or {}
    st.markdown("**Asal severity score**")
    st.write(exp.get("chain_text") or f"Skor hybrid {item['hybrid_score']:.2f}.")
    if item.get("pair_count", 1) > 1:
        st.caption(f"Skor issue diambil dari pasangan temuan dengan skor tertinggi di antara {item['pair_count']} "
                   f"pasangan ({exp.get('representative_pair') or '-'}).")
    for f in exp.get("review_flags", []):
        st.warning(f["text"])
    shap = exp.get("shap")
    if not shap:
        st.info("Penjelasan model (SHAP) tidak tersedia untuk issue ini.")
        return
    st.markdown("**Kata dalam laporan yang memengaruhi penilaian model**")
    c1, c2 = st.columns(2)
    with c1:
        st.caption("Menaikkan skor")
        if shap["raising"]:
            st.dataframe(_token_df(shap["raising"], "Kata"), hide_index=True, width="stretch")
        else:
            st.write("—")
    with c2:
        st.caption("Menurunkan skor")
        if shap["lowering"]:
            st.dataframe(_token_df(shap["lowering"], "Kata"), hide_index=True, width="stretch")
        else:
            st.write("—")
    m = st.columns(3)
    m[0].metric("Titik awal model", f"{shap['base_value']:.2f}",
                help="Rata-rata prediksi model atas seluruh data latih (nilai dasar SHAP).")
    m[1].metric("Pergeseran oleh kata", f"{shap['text_evidence']:.2f}",
                help="Jumlah pengaruh (absolut) kata-kata yang muncul di laporan. Nilai kecil berarti skor "
                     "sebagian besar hanyalah nilai rata-rata model.")
    if shap.get("unexplained") is not None:
        m[2].metric("Tidak terjelaskan oleh kata", f"{shap['unexplained']:+.2f}",
                    help="Bagian prediksi yang berasal dari ketiadaan kosakata (absent vocabulary bias), "
                         "bukan dari kata yang muncul.")
    st.caption(
        "Catatan: penjelasan ini menguraikan penilaian model atas teks gabungan SonarQube + OWASP ZAP"
        + (f" (prediksi {shap['predicted']:.2f})" if shap.get("predicted") is not None else "")
        + ". Skor hybrid pada issue adalah rata-rata dua penilaian terpisah ditambah eskalasi, sehingga angkanya "
          "dapat sedikit berbeda. Gunakan kata-kata di atas untuk menilai apakah skor masuk akal untuk aplikasi Anda.")


def _model_considerations(item: dict):
    exp = item.get("score_explanation") or {}
    lines = [exp.get("chain_text"), exp.get("model_reason")]
    flags = [f["text"] for f in exp.get("review_flags", [])]
    with st.container(border=True):
        st.markdown("**Pertimbangan sebelum memutuskan**")
        for ln in [l for l in lines if l]:
            st.caption(ln)
        for f in flags:
            st.caption(f"⚠ {f}")
        st.caption("Konteks ini ikut tercatat di audit trail saat Anda mengubah status atau prioritas.")


def _load_queue(batch_id: str) -> dict:
    """Menampilkan pratinjau ranking; bila pengguna berhak, mencatat rekomendasi untuk isu yang belum memiliki catatan."""
    run = api_client.dss_rank(batch_id, persist=False)
    if can("dss.save_run") and any(it.get("decision") is None for it in run["items"]):
        run = api_client.dss_rank(batch_id, persist=True)
    return run


def _justified(text: str) -> None:
    """
    Menampilkan teks panjang rata kiri-kanan (justify).

    Teks di-escape karena dapat berasal dari laporan pemindai yang di-upload pengguna; baris kosong
    dipertahankan sebagai pemisah paragraf.
    """
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", str(text or "")) if p.strip()]
    body = "".join(f"<p style='text-align:justify;margin:0 0 0.6rem 0'>{html.escape(p)}</p>" for p in paragraphs)
    st.markdown(body, unsafe_allow_html=True)


def build_decision_payload(perms: dict, *, status: str, note: str, owner: str, business_impact: int | None,
                           effort: int | None, due: datetime.date | None, priority: str) -> dict:
    """
    Menyusun isi PUT /decisions dari form tindak lanjut.

    Hanya kolom yang boleh diubah peran pengguna yang dikirim: widget yang dinonaktifkan tetap mengembalikan
    nilainya, dan mengirimnya akan ditolak backend (403) atau mengubah nilai "belum dinilai" menjadi pilihan
    eksplisit.

    Parameter:
        perms: hasil `_perms()` (kunci `triage` dan `override`).
        priority: "IKUTI" (ikuti rekomendasi) atau kode P1-P4.

    Mengembalikan:
        dict payload untuk `api_client.update_decision`.
    """
    payload = {"status": status, "reason": note.strip() or None}
    if perms.get("triage"):
        payload.update({
            "owner": owner.strip() or None, "asset_criticality": business_impact, "remediation_effort": effort,
            "sla_due_date": due.isoformat() if due else None,
        })
    if perms.get("override"):
        payload["chosen_action"] = None if priority == "IKUTI" else PRIORITY_TO_ACTION[priority]
    return payload


def _decision_form(item: dict, statuses: dict, disabled: bool):
    dec = item.get("decision") or {}
    key = item["decision_key"][:12]
    p = _perms()
    triage_off = disabled or not p["triage"]
    current_status = dec.get("status") or "OPEN"
    if p["triage"]:
        status_keys = [s for s in statuses if s != "ACCEPTED_RISK" or p["accept"] or current_status == s]
    else:  # peran yang hanya boleh memperbarui progres (pengembang)
        status_keys = [s for s in statuses if s in PROGRESS_STATUSES or s == current_status]
    with st.form(f"form_{key}", border=False):
        c1, c2, c3 = st.columns(3)
        status = c1.selectbox("Status", status_keys, index=status_keys.index(current_status),
                              format_func=lambda s: statuses[s], key=f"st_{key}", disabled=disabled)
        owner = c2.text_input("Penanggung jawab", value=dec.get("owner") or "", key=f"ow_{key}",
                              placeholder="Nama / tim", disabled=triage_off)
        due_default = dec.get("sla_due_date") or item["recommendation"].get("sla_due_date")
        due = c3.date_input("Due date", value=datetime.date.fromisoformat(due_default) if due_default else None,
                            key=f"due_{key}", format="DD/MM/YYYY", disabled=triage_off)
        c4, c5, c6 = st.columns(3)
        # None = belum dinilai analis; backend memakai nilai bawaan konfigurasi dan menandainya sebagai default.
        bi_opts = [None, *BI_OPTIONS]
        bi_val = dec.get("asset_criticality")
        bi = c4.selectbox("Dampak bisnis aset", bi_opts, index=bi_opts.index(bi_val) if bi_val in bi_opts else 0,
                          format_func=lambda v: NOT_ASSESSED if v is None else BI_OPTIONS[v], key=f"bi_{key}",
                          disabled=triage_off,
                          help="Seberapa penting aset ini bagi organisasi (1 = halaman publik tanpa data sensitif, "
                               "5 = autentikasi, transaksi, atau data pribadi). Tinggi atau Sangat tinggi dapat "
                               "menaikkan prioritas.")
        ef_opts = [None, *EFFORT_OPTIONS]
        ef_val = dec.get("remediation_effort")
        ef = c5.selectbox("Upaya perbaikan", ef_opts, index=ef_opts.index(ef_val) if ef_val in ef_opts else 0,
                          format_func=lambda v: NOT_ASSESSED if v is None else EFFORT_OPTIONS[v], key=f"ef_{key}",
                          disabled=triage_off,
                          help="Perkiraan waktu kerja perbaikan. Perbaikan yang lebih kecil didahulukan bila prioritasnya sama.")
        rec_p = item["recommendation"]["priority"]
        prio_opts = ["IKUTI"] + list(PRIORITY_STYLE)
        cur = dec.get("chosen_action")
        cur_p = next((p for p, a in PRIORITY_TO_ACTION.items() if a == cur), None)
        prio = c6.selectbox("Prioritas", prio_opts, index=prio_opts.index(cur_p) if cur_p else 0, key=f"pr_{key}",
                            disabled=disabled or not p["override"],
                            format_func=lambda p: f"Ikuti rekomendasi ({rec_p})" if p == "IKUTI" else PRIORITY_STYLE[p][1])
        note = st.text_area("Catatan / alasan", value=dec.get("reason") or "", key=f"nt_{key}", height=68,
                            placeholder="Wajib diisi bila status Risiko diterima, False positive, atau Ditunda.",
                            disabled=disabled)
        saved = st.form_submit_button("Simpan tindak lanjut", type="primary", disabled=disabled)
    if saved:
        payload = build_decision_payload(p, status=status, note=note, owner=owner, business_impact=bi,
                                         effort=ef, due=due, priority=prio)
        try:
            api_client.update_decision(item["decision_key"], payload)
        except ApiError as e:
            st.error(f"Gagal menyimpan: {e}")
        else:
            st.toast(f"Tindak lanjut {item['issue_code']} tersimpan.")
            st.rerun()


def _render_issue(item: dict, statuses: dict, logged_in: bool, dev: bool):
    dec = item.get("decision") or {}
    with st.container(border=True):
        top_l, top_r = st.columns([0.78, 0.22])
        with top_l:
            review = f" &nbsp; {REVIEW_BADGE}" if item.get("needs_review") else ""
            st.markdown(f"{_badge(item['priority'])}{review} &nbsp; **{item['title']}** "
                        f"<span style='color:#7f8c8d'>· {item['cwe_id']} · {item['issue_code']}</span>",
                        unsafe_allow_html=True)
        with top_r:
            status_label = statuses.get(dec.get("status") or "OPEN", "Belum ditangani")
            warn = " ⚠️ overdue" if dec.get("is_overdue") else ""
            st.markdown(f"<div style='text-align:right'>{status_label}{warn}</div>", unsafe_allow_html=True)

        _justified(item["why"])
        sev_color = SEVERITY_COLOR.get(item["severity"], "#7f8c8d")
        due = dec.get("sla_due_date") or item["recommendation"].get("sla_due_date")
        facts = [
            f"Severity <b style='color:{sev_color}'>{item['severity']} ({item['hybrid_score']:.2f})</b>",
            f"Terdeteksi: <b>{SOURCE_LABELS.get(item.get('source'), 'SAST dan DAST')}</b>",
            f"{len(item['files'])} file kode · {len(item['endpoints'])} endpoint",
            f"Tindakan: <b>{item['recommendation']['action_label']}</b>",
            f"Due date: <b>{_fmt_date(due)}</b>",
            f"PIC: <b>{dec.get('owner') or '—'}</b>",
        ]
        if item.get("priority_overridden"):
            facts.append(f"<i>prioritas diubah analis (rekomendasi {item['recommendation']['priority']})</i>")
        st.markdown(" &nbsp;|&nbsp; ".join(facts), unsafe_allow_html=True)

        t_fix, t_origin, t_where, t_act, t_hist = st.tabs(
            ["Cara memperbaiki", "Asal skor", "Lokasi terdampak", "Tindak lanjut", "History"])
        with t_origin:
            _render_score_origin(item)
        with t_fix:
            if item.get("mitigation_text"):
                _justified(item["mitigation_text"])
                st.caption("Sumber: saran solusi OWASP ZAP untuk alert ini.")
            else:
                st.info("Laporan scanner tidak menyertakan saran perbaikan untuk issue ini.")
            if item.get("sast_messages"):
                st.markdown("**Pesan SonarQube pada kode:**")
                for m in item["sast_messages"]:
                    st.markdown(f"- {m}")
        with t_where:
            st.markdown("**Endpoint aplikasi (OWASP ZAP):**")
            for e in item["endpoints"]:
                st.code(e, language=None)
            st.markdown(f"**File kode (SonarQube) — {len(item['files'])}:**")
            st.dataframe(pd.DataFrame({"File": item["files"]}), hide_index=True, width="stretch",
                         height=min(38 * (len(item["files"]) + 1), 280))
        with t_act:
            perms = _perms()
            if not logged_in:
                st.info(f"Login melalui {LOGIN_HINT} untuk mencatat tindak lanjut.")
                _decision_form(item, statuses, disabled=True)
            elif not (perms["triage"] or perms["progress"]):
                st.info("Role Anda hanya dapat melihat (baca saja).")
            else:
                _model_considerations(item)
                if not perms["triage"]:
                    st.caption("Role Anda dapat memperbarui progres (Sedang dikerjakan / Selesai) dan catatan.")
                elif not perms["accept"]:
                    st.caption("Status *Risiko diterima* hanya dapat ditetapkan oleh Manajer Keamanan atau Administrator.")
                _decision_form(item, statuses, disabled=False)
        with t_hist:
            if dec:
                try:
                    events = api_client.decision_events(item["decision_key"])
                except ApiError:
                    events = []
                if events:
                    st.dataframe(pd.DataFrame([{
                        "Waktu": e["created_at"][:16], "Oleh": e["actor"] or "sistem",
                        "Peristiwa": {"RECOMMENDED": "Rekomendasi sistem", "DECIDED": "Keputusan",
                                      "UPDATED": "Perubahan data"}.get(e["event_type"], e["event_type"]),
                        "Status": statuses.get(e["to_status"] or "", e["to_status"] or ""),
                        "Catatan": e["reason"] or "",
                        "Konteks model saat itu": " ".join(filter(None, [
                            (e.get("model_context") or {}).get("score_origin"),
                            (e.get("model_context") or {}).get("model_reason")])),
                    } for e in reversed(events)]), hide_index=True, width="stretch")
                else:
                    st.caption("Belum ada history.")
            else:
                st.caption("Belum ada history. History mulai dicatat setelah Anda login.")

        if dev:
            with st.expander("Detail teknis perhitungan (mode riset)"):
                st.caption(f"Skor urgensi MCDM {item['urgency']}/100 · preferensi {item['preference']} · "
                           f"peringkat MCDM {item['mcdm_rank']} · aturan {item['recommendation']['rule_id']}: "
                           f"{item['recommendation'].get('rule_text') or ''} · {item['pair_count']} pasangan SAST–DAST")
                st.dataframe(pd.DataFrame([{
                    "Kriteria": c["label"], "Arah": c["direction"], "Nilai": round(c["value"], 3),
                    "Bobot": c["weight"], "Terbobot": c["weighted"],
                } for c in item["criteria"]]), hide_index=True, width="stretch")


def _render_xlsx_button(col, batch_id: str) -> None:
    """
    Menampilkan tombol unduh catatan tindak lanjut (.xlsx).

    Tombol tetap terlihat; bila pengguna tidak memiliki hak `report.export` (atau ekspor gagal dimuat),
    tombol dinonaktifkan beserta keterangan alasannya.
    """
    label = "Download catatan tindak lanjut (.xlsx)"
    mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    if not can("report.export"):
        col.download_button(label, b"", file_name="Tindak_Lanjut.xlsx", mime=mime, disabled=True,
                            use_container_width=True,
                            help="Login dengan role yang memiliki hak export laporan untuk mengunduh file ini.")
        return
    try:
        xlsx = api_client.export_decisions_xlsx(batch_id)
    except ApiError as e:
        col.download_button(label, b"", file_name="Tindak_Lanjut.xlsx", mime=mime, disabled=True,
                            use_container_width=True, help=f"File tidak dapat dimuat: {e}")
        return
    col.download_button(label, xlsx, file_name=f"Tindak_Lanjut_{batch_id}.xlsx", mime=mime,
                        use_container_width=True)


def _queue_frame(items: list[dict], statuses: dict) -> pd.DataFrame:
    """Menyusun tabel daftar prioritas untuk unduhan CSV."""
    return pd.DataFrame([{
        "Urutan": it["rank"], "Prioritas": it["priority_label"], "Issue": it["title"], "CWE": it["cwe_id"],
        "Terdeteksi": SOURCE_LABELS.get(it.get("source"), "SAST dan DAST"),
        "Kode": it["issue_code"], "Severity": f"{it['severity']} ({it['hybrid_score']:.2f})",
        "Tindakan": it["recommendation"]["action_label"],
        "Due date": (it.get("decision") or {}).get("sla_due_date") or it["recommendation"].get("sla_due_date") or "",
        "Status": statuses.get((it.get("decision") or {}).get("status") or "OPEN"),
        "PIC": (it.get("decision") or {}).get("owner") or "",
        "File": len(it["files"]), "Endpoint": len(it["endpoints"]),
        "Cara memperbaiki": it.get("mitigation_text") or "",
        "Asal skor": (it.get("score_explanation") or {}).get("chain_text") or "",
        "Alasan model (SHAP)": (it.get("score_explanation") or {}).get("model_reason") or "",
        "Perlu diperiksa": " ".join(f["text"] for f in (it.get("score_explanation") or {}).get("review_flags", [])),
    } for it in items])


def render_page_priority():
    st.subheader("Prioritas Perbaikan")
    st.caption("Daftar kerja tim keamanan: seluruh temuan SonarQube dan OWASP ZAP pada satu session, diurutkan dari "
               "yang paling mendesak. Setiap issue menggabungkan temuan dengan alert dan CWE yang sama; issue yang "
               "terdeteksi di kode dan di aplikasi berjalan sekaligus mendapat bobot tambahan.")
    dev = bool(st.session_state.get("dev_mode"))
    try:
        cfg = api_client.dss_config()
        batches = api_client.list_dss_batches()
    except ApiError as e:
        st.error(f"Gagal memuat data: {e}")
        return
    if not batches:
        st.info("Belum ada hasil korelasi. Langkahnya: (1) upload laporan di **SonarQube (SAST)**, "
                "(2) upload laporan di **OWASP ZAP (DAST)**, (3) jalankan **Korelasi Hybrid**. "
                "Setelah itu prioritas perbaikan muncul di halaman ini.")
        return
    statuses = cfg["statuses"]

    ids = [b["batch_id"] for b in batches]
    by_id = {b["batch_id"]: b for b in batches}
    default = st.session_state.get("last_hybrid_batch")
    # Pilihan hasil scan dan unduhan CSV berbagi satu baris (50:50); tombol diisi setelah data dimuat.
    # Satu baris: pilihan hasil scan (50%) lalu dua tombol unduhan berbagi 50% sisanya.
    sel_col, csv_col, xlsx_col = st.columns([2, 1, 1], vertical_alignment="bottom")
    batch_id = sel_col.selectbox("Hasil scan:", ids, index=ids.index(default) if default in ids else 0,
                                 format_func=lambda b: batch_label(by_id[b]),
                                 help="Setiap hasil Korelasi Hybrid. Keputusan yang sudah dicatat ikut terbawa ke "
                                      "scan berikutnya untuk issue yang sama.")
    try:
        run = _load_queue(batch_id)
    except ApiError as e:
        st.error(f"Gagal menyusun prioritas: {e}")
        return
    items, summ = run["items"], run["summary"]
    csv_col.download_button("Download daftar prioritas (.csv)", _queue_frame(items, statuses).to_csv(index=False),
                            file_name=f"Prioritas_Perbaikan_{batch_id}.csv", mime="text/csv",
                            use_container_width=True)
    _render_xlsx_button(xlsx_col, batch_id)

    m = st.columns(6)
    m[0].metric("Issue terbuka", summ["open"], help=f"{run['pairs_count']} pasangan hybrid dan temuan pemindai tunggal digabung menjadi {summ['issues']} issue.")
    m[1].metric("P1 · Segera", summ["by_priority"]["P1"])
    m[2].metric("P2 · Terjadwal", summ["by_priority"]["P2"])
    m[3].metric("Perlu diperiksa", summ.get("needs_review", 0),
                help="Issue terbuka yang skornya dekat batas severity class atau hanya sedikit didukung bukti "
                     "dari teks laporan (berdasarkan penjelasan SHAP). Periksa sebelum bertindak.")
    m[4].metric("Overdue", summ["overdue"])
    m[5].metric("Selesai / ditutup", summ["closed"])

    f1, f2, f3 = st.columns([1, 1, 1])
    show = f1.radio("Tampilkan", ["Belum selesai", "Semua", "Sudah ditutup"], horizontal=True)
    prio_filter = f2.multiselect("Prioritas", list(PRIORITY_STYLE), default=[], placeholder="Semua prioritas",
                                 format_func=lambda p: PRIORITY_STYLE[p][1])
    owner_filter = f3.text_input("Penanggung jawab", placeholder="Saring berdasarkan PIC")
    only_review = st.checkbox("Hanya tampilkan issue yang perlu diperiksa", value=False)

    def visible(it):
        closed = (it.get("decision") or {}).get("is_closed", False)
        if show == "Belum selesai" and closed:
            return False
        if show == "Sudah ditutup" and not closed:
            return False
        if prio_filter and it["priority"] not in prio_filter:
            return False
        if owner_filter and owner_filter.lower() not in ((it.get("decision") or {}).get("owner") or "").lower():
            return False
        if only_review and not it.get("needs_review"):
            return False
        return True

    shown = [it for it in items if visible(it)]
    if not shown:
        st.success("Tidak ada issue yang cocok dengan filter ini.")
    logged_in = current_user() is not None
    if not logged_in:
        st.info(f"Anda dapat melihat prioritas tanpa login. Login melalui {LOGIN_HINT} untuk mencatat status, "
                "penanggung jawab, dan due date.")
    for it in shown:
        _render_issue(it, statuses, logged_in, dev)

    if dev and run.get("warnings"):
        with st.expander("Catatan metodologis (mode riset)"):
            for w in run["warnings"]:
                st.markdown(f"- {w}")
