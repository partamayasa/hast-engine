# backend/routers/v1/findings.py
"""Ingest laporan, skoring batch, riwayat pemindaian, dan korelasi hybrid."""
import time
from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend import engine
from backend.dss import service as dss_service
from backend.routers.deps import CurrentUser, get_db, get_optional_user, require_permission
from backend.config import load_unprocessing_domains
from backend.core.settings import get_settings
from backend.repositories import history as history_repo
from backend.services import scoring
from backend.services.parsers.reports import ReportParseError, decode_report, parse_sonarqube, parse_zap

router = APIRouter(prefix="/api/v1", tags=["Temuan & History"])

ScannerPrefix = Literal["SAST", "DAST"]


# ---------------------------------------------------------------------------
# Ingest laporan
# ---------------------------------------------------------------------------
async def _read_upload(file: UploadFile) -> bytes:
    limit = get_settings().max_upload_mb * 1024 * 1024
    raw = await file.read(limit + 1)
    if len(raw) > limit:
        raise HTTPException(status_code=413, detail=f"Ukuran file melebihi batas {get_settings().max_upload_mb}MB.")
    return raw


@router.post("/ingest/sonarqube")
async def ingest_sonarqube(file: UploadFile = File(...)):
    try:
        records = parse_sonarqube(decode_report(await _read_upload(file)), auto_fetch=False)
    except ReportParseError as e:
        raise HTTPException(status_code=400, detail=f"Eror membaca file JSON SonarQube: {e}")
    return {"status": "success", "scanner": "SAST", "count": len(records), "records": records}


@router.post("/ingest/zap")
async def ingest_zap(file: UploadFile = File(...)):
    try:
        records = parse_zap(decode_report(await _read_upload(file)), load_unprocessing_domains())
    except ReportParseError as e:
        raise HTTPException(status_code=400, detail=f"Eror membaca file JSON OWASP ZAP: {e}")
    return {"status": "success", "scanner": "DAST", "count": len(records), "records": records}


# ---------------------------------------------------------------------------
# Skoring batch
# ---------------------------------------------------------------------------
class BatchCreate(BaseModel):
    scanner: ScannerPrefix
    records: list[dict] = Field(min_length=1, max_length=20000)


@router.post("/batches")
def create_batch(data: BatchCreate, db: Session = Depends(get_db)):
    start = time.time()
    try:
        scored = scoring.score_records(data.scanner, data.records)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kesalahan internal mesin penilai: {e}")
    duration = time.time() - start
    batch_id = scoring.new_batch_id(data.scanner)
    history_repo.save_findings(db, batch_id, scoring.SCANNER_LABELS[data.scanner], scored,
                               execution_duration=duration, model_version=scoring.model_version())
    return {"status": "success", "batch_id": batch_id, "execution_duration": duration, "records": scored}


# ---------------------------------------------------------------------------
# Riwayat
# ---------------------------------------------------------------------------
@router.get("/history")
def list_history(scanner_type: str = Query(...), db: Session = Depends(get_db)):
    return {"rows": history_repo.list_by_scanner(db, scanner_type)}


@router.get("/batches")
def list_batches(scanner_type: str | None = None, db: Session = Depends(get_db)):
    return {"batches": history_repo.list_batches(db, scanner_type)}


@router.get("/batches/{batch_id}")
def get_batch(batch_id: str, db: Session = Depends(get_db)):
    rows = history_repo.list_batch(db, batch_id)
    if not rows:
        raise HTTPException(status_code=404, detail=f"Session {batch_id} tidak ditemukan.")
    return {"batch_id": batch_id, "rows": rows}


@router.delete("/batches/{batch_id}")
def delete_batch(batch_id: str, db: Session = Depends(get_db),
                 _user: CurrentUser = Depends(require_permission("history.delete"))):
    return {"status": "success", "deleted": history_repo.delete_batch(db, batch_id)}


@router.delete("/history")
def clear_history(scanner_type: str = Query(...), db: Session = Depends(get_db),
                  _user: CurrentUser = Depends(require_permission("history.delete"))):
    return {"status": "success", "deleted": history_repo.clear_scanner(db, scanner_type)}


class ShapComputeItem(BaseModel):
    id: int
    sast_description: str = ""
    dast_description: str = ""


class ShapComputeInput(BaseModel):
    items: list[ShapComputeItem] = Field(max_length=20000)


@router.post("/history/shap")
def compute_and_store_shap(data: ShapComputeInput, db: Session = Depends(get_db)):
    """Menghitung dekomposisi SHAP yang belum ada untuk baris tersimpan lalu menyimpannya (sebelumnya thread UI)."""
    if not data.items:
        return {"status": "success", "results": []}
    results = engine.calculate_dynamic_shap_batch([(i.sast_description, i.dast_description) for i in data.items])
    updates = []
    for item, res in zip(data.items, results):
        upd = {"id": item.id}
        for f in ("shap_base_value", "shap_total_pos", "shap_total_neg", "absent_vocab_bias",
                  "shap_predicted_score"):
            if f in res:
                upd[f] = float(res[f])
        upd["shap_positive"] = res.get("shap_positive", "N/A")
        upd["shap_negative"] = res.get("shap_negative", "N/A")
        if item.sast_description:
            upd["sast_description"] = item.sast_description
        if item.dast_description:
            upd["dast_description"] = item.dast_description
        updates.append(upd)
    history_repo.update_shap_fields(db, updates)
    return {"status": "success", "results": [{"id": i.id, **r} for i, r in zip(data.items, results)]}


# ---------------------------------------------------------------------------
# Korelasi hybrid
# ---------------------------------------------------------------------------
class CorrelationInput(BaseModel):
    sast_batch_id: str
    dast_batch_id: str


def _load_pair_sources(db: Session, data: CorrelationInput):
    sast = history_repo.list_batch(db, data.sast_batch_id)
    dast = history_repo.list_batch(db, data.dast_batch_id)
    if not sast or not dast:
        raise HTTPException(status_code=404, detail="Session SAST atau DAST tidak ditemukan.")
    return sast, dast


@router.post("/correlation/preview")
def correlation_preview(data: CorrelationInput, db: Session = Depends(get_db)):
    sast, dast = _load_pair_sources(db, data)
    pairs = scoring.preview_pairs(sast, dast)
    return {"status": "success", "count": len(pairs), "pairs": pairs}


def _record_issues(db: Session, batch_id: str, user: CurrentUser | None) -> dict:
    """
    Mencatat issue dan rekomendasi DSS untuk sesi hybrid baru bila pengguna berhak menyimpan.

    Kegagalan pencatatan tidak membatalkan hasil korelasi: perubahan DSS dijalankan di dalam savepoint
    dan alasannya dikembalikan agar UI dapat menampilkannya.

    Mengembalikan:
        dict `{recorded, reason, issues, run_id}`; `reason` bernilai "not_logged_in", "not_permitted",
        atau "failed" bila tidak tercatat.
    """
    if user is None:
        return {"recorded": False, "reason": "not_logged_in"}
    if not user.can("dss.save_run"):
        return {"recorded": False, "reason": "not_permitted"}
    try:
        with db.begin_nested():
            run = dss_service.rank_batch(db, batch_id, persist=True, actor=user.username)
    except (LookupError, ValueError) as e:
        return {"recorded": False, "reason": "failed", "detail": str(e)}
    return {"recorded": True, "issues": len(run["items"]), "run_id": run["run_id"]}


@router.post("/correlation/run")
def correlation_run(data: CorrelationInput, db: Session = Depends(get_db),
                    user: CurrentUser | None = Depends(get_optional_user)):
    """
    Menjalankan korelasi hybrid dan menyimpan hasilnya. Bila pengguna login dengan hak menyimpan prioritas,
    issue dan rekomendasinya langsung dicatat di DSS (pelaku tercatat di audit trail).
    """
    sast, dast = _load_pair_sources(db, data)
    start = time.time()
    pairs = scoring.preview_pairs(sast, dast)
    if not pairs:
        return {"status": "success", "batch_id": None, "records": [], "execution_duration": 0.0,
                "dss": {"recorded": False, "reason": "no_pairs"}}
    try:
        records = scoring.score_pairs(pairs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kesalahan internal Hybrid Engine: {e}")
    records.sort(key=lambda r: r["predicted_cvss4_score"], reverse=True)
    duration = time.time() - start
    batch_id = scoring.new_batch_id("HAST")
    history_repo.save_findings(db, batch_id, history_repo.HYBRID_SCANNER, records,
                               execution_duration=duration, model_version=scoring.model_version())
    return {"status": "success", "batch_id": batch_id, "execution_duration": duration, "records": records,
            "source_batches": {"sast": data.sast_batch_id, "dast": data.dast_batch_id},
            "dss": _record_issues(db, batch_id, user)}
