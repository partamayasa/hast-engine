# backend/routers/v1/system.py
"""Metadata root, ringkasan sistem, laporan sampel, dan pemeriksaan kesehatan (jalur dipertahankan dari v1)."""
import json
import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from backend import model_loader
from backend.config import load_active_model_name, load_backend_metadata, load_hybrid_escalation_rate
from backend.core.settings import get_settings

router = APIRouter(tags=["Sistem"])

SAMPLE_FILES = {"SonarQube_Report.json", "OWASP_ZAP_Report.json"}
NA_SUMMARY = {
    "api_title": "N/A", "api_description": "N/A", "app_version": "N/A", "active_model": "N/A",
    "escalation_rate": "N/A", "variety_cwe": "N/A", "number_cvss4_records": "N/A",
    "dataset_timestamp": "N/A", "last_updated": "N/A",
}
NO_CACHE = {"Cache-Control": "no-cache, no-store, must-revalidate"}


@router.get("/")
def read_root(request: Request):
    meta = load_backend_metadata()
    return {
        "status": "online",
        "title": request.app.title,
        "version": request.app.version,
        "description": meta["description"],
        "escalation_rate": load_hybrid_escalation_rate(),
        "active_model": load_active_model_name(),
        "dataset_timestamp": meta.get("dataset_timestamp", "2026-10-13"),
    }


@router.get("/api/v1/health")
def health():
    return {"status": "ok", "models_loaded": model_loader.models_loaded()}


@router.get("/sample-reports/{filename}")
def download_sample_report(filename: str):
    if filename not in SAMPLE_FILES:
        raise HTTPException(status_code=404, detail="File sampel tidak ditemukan.")
    file_path = get_settings().sample_reports_dir / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File tidak ditemukan pada server.")
    return FileResponse(path=str(file_path), media_type="application/json", filename=filename)


@router.get("/system_summary.json")
def get_system_summary():
    path = get_settings().system_summary_path
    if not os.path.exists(path):
        return JSONResponse(content=NA_SUMMARY, headers=NO_CACHE)
    with open(path, "r", encoding="utf-8") as f:
        return JSONResponse(content=json.load(f), headers=NO_CACHE)
