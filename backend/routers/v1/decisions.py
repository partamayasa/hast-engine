# backend/routers/v1/decisions.py
"""Keputusan analis atas rekomendasi DSS: daftar, keputusan, jejak audit, ekspor, dan tingkat kesesuaian."""
import io

import pandas as pd
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.dss.evaluation import agreement_rate
from backend.repositories import dss as dss_repo
from backend.core.roles import PROGRESS_STATUSES
from backend.routers.deps import CurrentUser, get_current_user, get_db, require_permission

router = APIRouter(prefix="/api/v1/decisions", tags=["Keputusan"])


@router.get("")
def list_decisions(batch_id: str | None = None, status: str | None = None, db: Session = Depends(get_db)):
    return {"decisions": dss_repo.list_decisions(db, batch_id, status)}


@router.get("/agreement")
def agreement(db: Session = Depends(get_db)):
    """
    Dari isu yang sudah ditindaklanjuti analis (decided_by terisi), porsi yang prioritas efektifnya sama dengan
    rekomendasi sistem. Memilih "ikuti rekomendasi" (chosen_action = null) dihitung sebagai sesuai.
    """
    rows = [r for r in dss_repo.list_decisions(db) if r["decided_by"]]
    return agreement_rate([(r["recommended_action"], r["chosen_action"] or r["recommended_action"]) for r in rows])


@router.get("/export.xlsx")
def export_xlsx(batch_id: str | None = None, db: Session = Depends(get_db),
                _u: CurrentUser = Depends(require_permission("report.export"))):
    rows = dss_repo.list_decisions(db, batch_id)
    cache: dict = {}
    for r in rows:
        exp = (dss_repo.run_item(db, r["last_run_id"], r["decision_key"], cache) or {}).get("score_explanation") or {}
        r["_score_origin"] = exp.get("chain_text") or ""
        r["_model_reason"] = exp.get("model_reason") or ""
        r["_review_notes"] = " ".join(f["text"] for f in exp.get("review_flags", []))
    df = pd.DataFrame([{
        "Issue": r["title"], "CWE ID": r["cwe_id"], "Prioritas": r["priority_label"],
        "Rekomendasi Sistem": r["recommended_action_label"], "Aturan": r["recommended_rule_id"],
        "Prioritas Ditetapkan Analis": r["chosen_action_label"], "Status": r["status_label"],
        "Penanggung Jawab": r["owner"], "Catatan": r["reason"],
        "Dampak Bisnis": r["business_impact_label"], "Upaya Perbaikan": r["effort_label"],
        "Overdue": "Ya" if r["is_overdue"] else "",
        "Asal Skor": r["_score_origin"], "Alasan Model (SHAP)": r["_model_reason"], "Perlu Diperiksa": r["_review_notes"],
        "Due Date (SLA)": r["sla_due_date"], "Diputuskan Oleh": r["decided_by"], "Waktu Keputusan": r["decided_at"],
        "Session Terakhir": r["last_batch_id"], "Kunci Keputusan": r["decision_key"],
    } for r in rows])
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as xw:
        df.to_excel(xw, index=False, sheet_name="Keputusan")
    buf.seek(0)
    name = f"Log_Keputusan_DSS_{batch_id or 'semua'}.xlsx"
    return StreamingResponse(buf, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


class DecisionUpdate(BaseModel):
    chosen_action: str | None = None
    status: str | None = None
    reason: str | None = Field(default=None, max_length=2000)
    asset_criticality: int | None = Field(default=None, ge=1, le=5)
    remediation_effort: int | None = Field(default=None, ge=1, le=3)
    sla_due_date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    owner: str | None = Field(default=None, max_length=128)


def _authorize_decision_change(user: CurrentUser, changes: dict) -> None:
    """RBAC tingkat kolom untuk pembaruan keputusan."""
    def deny(what: str):
        raise HTTPException(status_code=403, detail=f"Role Anda tidak memiliki hak untuk {what}.")

    triage_fields = {"owner", "sla_due_date", "asset_criticality", "remediation_effort"}
    if triage_fields & set(changes) and not user.can("decision.triage"):
        deny("mengubah penanggung jawab, due date, dampak bisnis, atau upaya")
    if "chosen_action" in changes and not user.can("decision.override_priority"):
        deny("mengubah prioritas")
    if "status" in changes:
        st = changes["status"]
        if st == "ACCEPTED_RISK" and not user.can("decision.accept_risk"):
            deny("menetapkan status Risiko diterima (memerlukan Manajer Keamanan)")
        if st not in PROGRESS_STATUSES and st != "ACCEPTED_RISK" and not user.can("decision.triage"):
            deny("menetapkan status ini")
        if st in PROGRESS_STATUSES and not (user.can("decision.triage") or user.can("decision.update_progress")):
            deny("memperbarui status")
    if "reason" in changes and not (user.can("decision.triage") or user.can("decision.update_progress")):
        deny("menulis catatan")


@router.put("/{decision_key}")
def update(decision_key: str, data: DecisionUpdate, db: Session = Depends(get_db),
           user: CurrentUser = Depends(get_current_user)):
    changes = data.model_dump(exclude_unset=True)
    current = dss_repo.get_decision(db, decision_key)
    if current is not None:
        # Hanya kolom yang benar-benar berubah yang diperiksa haknya (form mengirim semua kolom).
        current_vals = dss_repo.decision_to_dict(current)
        changes = {k: v for k, v in changes.items() if current_vals.get(k) != v}
    _authorize_decision_change(user, changes)
    reason_after = changes.get("reason", current.reason if current is not None else None)
    if changes.get("status") in ("ACCEPTED_RISK", "FALSE_POSITIVE", "DEFERRED") and not (reason_after or "").strip():
        raise HTTPException(status_code=422, detail="Status ini wajib disertai alasan.")
    try:
        d = dss_repo.update_decision(db, decision_key, changes, user.username)
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return dss_repo.decision_to_dict(d)


@router.get("/{decision_key}/events")
def events(decision_key: str, db: Session = Depends(get_db)):
    return {"events": dss_repo.list_events(db, decision_key)}
