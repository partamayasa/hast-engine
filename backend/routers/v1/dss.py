# backend/routers/v1/dss.py
"""Endpoint DSS: konfigurasi, ranking, pembobotan AHP, analisis sensitivitas, run, dan evaluasi."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.dss import service
from backend.dss.ahp import CR_THRESHOLD, ahp_weights
from backend.dss.config import load_dss_config, save_dss_config, validate_dss_config
from backend.dss.evaluation import rank_correlation, top_k_overlap
from backend.dss.mcdm import METHODS
from backend.dss.recommender import ACTIONS, BUSINESS_IMPACT, EFFORT, PRIORITY_LABELS, STATUSES
from backend.repositories import dss as dss_repo
from backend.routers.deps import CurrentUser, get_db, get_optional_user, require_permission

router = APIRouter(prefix="/api/v1/dss", tags=["DSS"])


def _err(e: Exception):
    if isinstance(e, LookupError):
        raise HTTPException(status_code=404, detail=str(e))
    if isinstance(e, ValueError):
        raise HTTPException(status_code=422, detail=str(e))
    raise e


@router.get("/config")
def get_config():
    cfg = load_dss_config()
    return {**cfg, "available_methods": list(METHODS), "actions": ACTIONS, "statuses": STATUSES,
            "priorities": PRIORITY_LABELS, "business_impact_levels": BUSINESS_IMPACT, "effort_levels": EFFORT}


@router.put("/config")
def put_config(cfg: dict, _m: CurrentUser = Depends(require_permission("settings.manage"))):
    try:
        for k in ("available_methods", "actions", "statuses", "priorities", "business_impact_levels", "effort_levels"):
            cfg.pop(k, None)
        return save_dss_config(cfg)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


class RankInput(BaseModel):
    batch_id: str
    method: str | None = None
    weights: dict[str, float] | None = None
    escalation_rate: float | None = Field(default=None, ge=0.0, le=1.0)
    persist: bool = True


def _is_what_if(data: RankInput) -> bool:
    """Menentukan apakah permintaan ranking menyimpang dari konfigurasi DSS yang berlaku."""
    if data.weights or data.escalation_rate is not None:
        return True
    return bool(data.method) and data.method.upper() != str(load_dss_config().get("method", "")).upper()


@router.post("/rank")
def rank(data: RankInput, db: Session = Depends(get_db), user: CurrentUser | None = Depends(get_optional_user)):
    """
    Memeringkat alternatif dari satu sesi hybrid. Siapa pun boleh melihat pratinjau (persist=false); menyimpan run
    (beserta rekomendasi yang dilekatkan ke temuan) memerlukan login agar pelakunya tercatat.
    """
    if data.persist and user is None:
        raise HTTPException(status_code=401, detail="Menyimpan hasil ranking memerlukan login.")
    if data.persist and not user.can("dss.save_run"):
        raise HTTPException(status_code=403, detail="Role Anda hanya dapat melihat prioritas (tidak menyimpan).")
    if data.persist and _is_what_if(data):
        # Run yang disimpan melekatkan rekomendasi ke isu; simulasi what-if tidak boleh menggantikan rekomendasi
        # resmi. Kebijakan permanen diubah melalui PUT /config atau AHP.
        raise HTTPException(status_code=422, detail="Simulasi what-if (metode, bobot, atau escalation rate berbeda "
                                                    "dari konfigurasi) hanya dapat dijalankan dengan persist=false.")
    try:
        run = service.rank_batch(db, data.batch_id, data.method, data.weights, data.escalation_rate,
                                 persist=data.persist, actor=user.username if user else None)
    except (LookupError, ValueError) as e:
        _err(e)
    run["summary"] = service.summary(run)
    return run


class AhpInput(BaseModel):
    criteria: list[str] = Field(min_length=1, max_length=10)
    matrix: list[list[float]]
    save: bool = False
    source: str | None = Field(default=None, max_length=200, description="Mis. 'Rata-rata geometrik 3 pakar'")


@router.post("/ahp")
def ahp(data: AhpInput, user: CurrentUser | None = Depends(get_optional_user)):
    if len(data.matrix) != len(data.criteria):
        raise HTTPException(status_code=422, detail="Ukuran matriks harus sama dengan jumlah kriteria.")
    try:
        res = ahp_weights(data.matrix)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    out = {
        "criteria": data.criteria, "weights": dict(zip(data.criteria, [round(float(x), 6) for x in res.weights])),
        "lambda_max": round(res.lambda_max, 6), "ci": round(res.ci, 6), "cr": round(res.cr, 6), "ri": res.ri,
        "is_consistent": res.is_consistent, "threshold": CR_THRESHOLD, "saved": False,
    }
    if data.save:
        if user is None or not user.can("settings.manage"):
            raise HTTPException(status_code=403, detail="Menyimpan bobot AHP memerlukan hak priority settings.")
        if not res.is_consistent:
            raise HTTPException(status_code=422, detail=f"CR = {res.cr:.4f} > {CR_THRESHOLD}: matriks tidak konsisten, "
                                                        "bobot tidak disimpan. Tinjau ulang perbandingan berpasangan.")
        cfg = load_dss_config()
        known = {c["key"] for c in cfg["criteria"]}
        if set(data.criteria) - known:
            raise HTTPException(status_code=422, detail="Kriteria AHP harus sesuai dengan kriteria konfigurasi DSS.")
        for c in cfg["criteria"]:
            if c["key"] in out["weights"]:
                c["weight"], c["enabled"] = out["weights"][c["key"]], True
            else:
                c["enabled"] = False
        cfg["weighting_source"] = "ahp"
        cfg["ahp"] = {"criteria": data.criteria, "matrix": data.matrix, "consistency_ratio": out["cr"],
                      "source": data.source, "saved_by": user.username}
        validate_dss_config(cfg)
        save_dss_config(cfg)
        out["saved"] = True
    return out


class SensitivityInput(BaseModel):
    batch_id: str
    method: str | None = None
    steps: list[float] | None = None
    k: int = Field(default=10, ge=1, le=100)


@router.post("/sensitivity")
def sensitivity(data: SensitivityInput, db: Session = Depends(get_db)):
    try:
        return service.sensitivity(db, data.batch_id, data.method, data.steps, data.k)
    except (LookupError, ValueError) as e:
        _err(e)


class ErSensitivityInput(BaseModel):
    batch_id: str
    rates: list[float] = Field(min_length=1, max_length=50)
    method: str | None = None
    k: int = Field(default=10, ge=1, le=100)


@router.post("/sensitivity/escalation-rate")
def er_sensitivity(data: ErSensitivityInput, db: Session = Depends(get_db)):
    if any(r < 0 or r > 1 for r in data.rates):
        raise HTTPException(status_code=422, detail="Escalation rate harus di antara 0 dan 1.")
    try:
        return service.er_sensitivity(db, data.batch_id, data.rates, data.method, data.k)
    except (LookupError, ValueError) as e:
        _err(e)


@router.get("/runs")
def runs(batch_id: str | None = None, db: Session = Depends(get_db)):
    return {"runs": dss_repo.list_runs(db, batch_id)}


@router.get("/runs/{run_id}")
def run_detail(run_id: str, db: Session = Depends(get_db)):
    run = dss_repo.get_run(db, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run DSS tidak ditemukan.")
    return run


class EvaluateInput(BaseModel):
    run_id: str
    expert_ranking: list[str] = Field(min_length=2, description="Kode issue (key_id) diurutkan dari prioritas tertinggi")
    k: int = Field(default=10, ge=1, le=100)


@router.post("/evaluate")
def evaluate(data: EvaluateInput, db: Session = Depends(get_db),
             _u: CurrentUser = Depends(require_permission("research.evaluate"))):
    """Membandingkan ranking DSS yang tersimpan (dan baseline urutan skor saja) dengan ranking pakar."""
    run = dss_repo.get_run(db, data.run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run DSS tidak ditemukan.")
    dss_order = [it["key_id"] for it in run["items"]]
    baseline = [it["key_id"] for it in sorted(run["items"], key=lambda it: (-it["hybrid_score"], it["key_id"]))]
    return {
        "run_id": data.run_id, "method": run["method"], "n_alternatives": len(dss_order),
        "dss_vs_expert": {**rank_correlation(dss_order, data.expert_ranking),
                          **top_k_overlap(dss_order, data.expert_ranking, data.k)},
        "score_only_vs_expert": {**rank_correlation(baseline, data.expert_ranking),
                                 **top_k_overlap(baseline, data.expert_ranking, data.k)},
        "note": "Baseline 'score_only' = urutan skor hybrid apa adanya (tanpa MCDM).",
    }
