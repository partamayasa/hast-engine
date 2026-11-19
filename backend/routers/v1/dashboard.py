# backend/routers/v1/dashboard.py
"""Ringkasan dasbor DSS (hanya baca): angka kunci, beban kerja, tenggat, dan sebaran temuan pemindaian."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.dss.dashboard import build_summary
from backend.repositories import dss as dss_repo
from backend.repositories import history as history_repo
from backend.routers.deps import get_db

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])


@router.get("")
def dashboard(due_soon_days: int = Query(7, ge=1, le=90), batch_limit: int = Query(30, ge=1, le=200),
              db: Session = Depends(get_db)):
    """Mengembalikan ringkasan dasbor dari keputusan DSS dan riwayat pemindaian yang tersimpan."""
    decisions = dss_repo.list_decisions(db)
    cache: dict = {}
    for d in decisions:
        if d["is_closed"]:
            continue
        exp = (dss_repo.run_item(db, d["last_run_id"], d["decision_key"], cache) or {}).get("score_explanation") or {}
        d["needs_review"] = bool(exp.get("review_flags"))
    return build_summary(decisions, history_repo.batch_stats(db, batch_limit), due_soon_days=due_soon_days)
