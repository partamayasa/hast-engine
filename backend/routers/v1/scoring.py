# backend/routers/v1/scoring.py
"""Endpoint skoring satu item (kontrak v1 tidak berubah) + SHAP batch."""
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend import engine

router = APIRouter(tags=["Penilaian Skor"])


class VulnerabilityInput(BaseModel):
    scanner_type: str
    description: str
    component: str
    issue_type: Optional[str] = ""
    has_cwe_tag: Optional[bool] = True
    target_scope_domain: Optional[str] = ""


class HybridVulnerabilityInput(BaseModel):
    sast_description: str
    dast_description: str
    cwe_id: str
    sast_component: Optional[str] = ""
    dast_component: Optional[str] = ""


class ShapPair(BaseModel):
    sast_description: str = ""
    dast_description: str = ""


class ShapBatchInput(BaseModel):
    pairs: list[ShapPair] = Field(default_factory=list, max_length=5000)


@router.post("/predict")
def predict_vulnerability_score(data: VulnerabilityInput):
    if not data.description.strip():
        raise HTTPException(status_code=400, detail="Deskripsi kerentanan kosong.")
    try:
        res = engine.run_single_prediction(
            data.scanner_type, data.description, data.component, data.issue_type, data.has_cwe_tag
        )
        return {"status": "success", **res}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kesalahan internal mesin penilai: {str(e)}")


@router.post("/predict/hybrid")
def predict_hybrid_score(data: HybridVulnerabilityInput):
    if not data.sast_description.strip() and not data.dast_description.strip():
        raise HTTPException(status_code=400, detail="Deskripsi SAST dan DAST tidak boleh kosong.")
    try:
        res = engine.run_hybrid_prediction(
            sast_desc=data.sast_description, dast_desc=data.dast_description, cwe_id=data.cwe_id
        )
        return {"status": "success", **res}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kesalahan internal Hybrid Engine: {str(e)}")


@router.post("/predict/shap")
def predict_shap_explanation(data: HybridVulnerabilityInput):
    try:
        res = engine.calculate_dynamic_shap(data.sast_description, data.dast_description)
        return {"status": "success", **res}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kesalahan internal SHAP Engine: {str(e)}")


@router.post("/api/v1/scoring/shap/batch")
def shap_batch(data: ShapBatchInput):
    """Dekomposisi SHAP batch (satu panggilan TreeExplainer untuk seluruh teks unik)."""
    try:
        results = engine.calculate_dynamic_shap_batch([(p.sast_description, p.dast_description) for p in data.pairs])
        return {"status": "success", "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Kesalahan internal SHAP Engine: {str(e)}")
