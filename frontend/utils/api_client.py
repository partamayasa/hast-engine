# frontend/utils/api_client.py
"""
Klien HTTP untuk backend FastAPI. Pada v2, ini SATU-SATUNYA jalur UI untuk membaca atau menulis data.

Setiap panggilan memakai timeout dan memunculkan ApiError dengan pesan untuk pengguna (bahasa Indonesia)
alih-alih menghentikan skrip Streamlit.
"""
from typing import Any

import pandas as pd
import requests

from frontend.utils.config import API_BASE_URL, load_app_config

API_URL = f"{API_BASE_URL}/predict"
DEFAULT_TIMEOUT = 30
LONG_TIMEOUT = 600  # skoring batch / korelasi laporan berukuran besar


class ApiError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def _token() -> str | None:
    try:
        import streamlit as st
        return st.session_state.get("auth_token")
    except Exception:
        return None


def _request(method: str, path: str, timeout: int = DEFAULT_TIMEOUT, auth: bool = True, **kwargs) -> Any:
    headers = kwargs.pop("headers", {}) or {}
    token = _token() if auth else None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.request(method, f"{API_BASE_URL}{path}", headers=headers, timeout=timeout, **kwargs)
    except requests.exceptions.ConnectionError:
        raise ApiError("Gagal terhubung ke Backend FastAPI. Pastikan server uvicorn aktif.")
    except requests.exceptions.Timeout:
        raise ApiError("Permintaan ke Backend FastAPI melebihi batas waktu.")
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        if isinstance(detail, list):
            detail = "; ".join(str(d.get("msg", d)) for d in detail)
        raise ApiError(str(detail), resp.status_code)
    if not resp.content:
        return None
    ctype = resp.headers.get("content-type", "")
    return resp.json() if "json" in ctype else resp.content


# ---------------------------------------------------------------------------
# Fungsi bantu lama untuk satu item (dipertahankan: dipakai tab simulasi / black-box)
# ---------------------------------------------------------------------------
def hit_hybrid_api(sast_desc, dast_desc, cwe_id):
    """Mengirim deskripsi kerentanan yang berkorelasi ke endpoint prediksi hybrid di backend."""
    payload = {"sast_description": sast_desc, "dast_description": dast_desc, "cwe_id": cwe_id,
               "model_engine": load_app_config().get("active_model", "Random Forest")}
    try:
        return _request("POST", "/predict/hybrid", json=payload)
    except ApiError:
        return None


def hit_shap_api(sast_desc, dast_desc):
    """Mengirim data deskripsi ke endpoint perhitungan SHAP di backend."""
    try:
        return _request("POST", "/predict/shap",
                        json={"sast_description": sast_desc, "dast_description": dast_desc, "cwe_id": ""})
    except ApiError:
        return {"shap_positive": "N/A", "shap_negative": "N/A"}


def predict_single(payload: dict) -> dict:
    return _request("POST", "/predict", json=payload)


# ---------------------------------------------------------------------------
# Ingest, batch, dan riwayat
# ---------------------------------------------------------------------------
def ingest_report(scanner: str, filename: str, raw_bytes: bytes) -> dict:
    path = "/api/v1/ingest/sonarqube" if scanner == "SAST" else "/api/v1/ingest/zap"
    return _request("POST", path, timeout=LONG_TIMEOUT,
                    files={"file": (filename, raw_bytes, "application/json")})


def create_batch(scanner: str, records: list[dict]) -> dict:
    return _request("POST", "/api/v1/batches", timeout=LONG_TIMEOUT, json={"scanner": scanner, "records": records})


def list_history(scanner_type: str) -> pd.DataFrame:
    rows = _request("GET", "/api/v1/history", params={"scanner_type": scanner_type})["rows"]
    return pd.DataFrame(rows)


def list_batches(scanner_type: str | None = None) -> list[dict]:
    params = {"scanner_type": scanner_type} if scanner_type else {}
    return _request("GET", "/api/v1/batches", params=params)["batches"]


def get_batch(batch_id: str) -> pd.DataFrame:
    return pd.DataFrame(_request("GET", f"/api/v1/batches/{batch_id}")["rows"])


def delete_batch(batch_id: str) -> int:
    return _request("DELETE", f"/api/v1/batches/{batch_id}")["deleted"]


def clear_history(scanner_type: str) -> int:
    return _request("DELETE", "/api/v1/history", params={"scanner_type": scanner_type})["deleted"]


def compute_history_shap(items: list[dict]) -> list[dict]:
    """items: [{id, sast_description, dast_description}] -> hasil SHAP, disimpan di sisi server."""
    return _request("POST", "/api/v1/history/shap", timeout=LONG_TIMEOUT, json={"items": items})["results"]


def correlation_preview(sast_batch_id: str, dast_batch_id: str) -> list[dict]:
    return _request("POST", "/api/v1/correlation/preview", timeout=LONG_TIMEOUT,
                    json={"sast_batch_id": sast_batch_id, "dast_batch_id": dast_batch_id})["pairs"]


def correlation_run(sast_batch_id: str, dast_batch_id: str) -> dict:
    return _request("POST", "/api/v1/correlation/run", timeout=LONG_TIMEOUT,
                    json={"sast_batch_id": sast_batch_id, "dast_batch_id": dast_batch_id})


# ---------------------------------------------------------------------------
# Riset & SUS
# ---------------------------------------------------------------------------
def research_dataset_metadata() -> dict | None:
    return _request("GET", "/api/v1/research/dataset-metadata")["metadata"]


def research_class_distribution() -> list[dict]:
    return _request("GET", "/api/v1/research/class-distribution")["rows"]


def research_model_evaluation(algorithm: str = "Random Forest Regressor") -> dict | None:
    return _request("GET", "/api/v1/research/model-evaluation", params={"algorithm": algorithm})["evaluation"]


def submit_sus(respondent_name: str, profession: str, answers: dict, ui_version: str = "v2-dss") -> dict:
    return _request("POST", "/api/v1/sus", auth=False, json={
        "respondent_name": respondent_name, "profession": profession, "answers": answers, "ui_version": ui_version})


def list_sus() -> list[dict]:
    return _request("GET", "/api/v1/sus")["rows"]


# ---------------------------------------------------------------------------
# Autentikasi
# ---------------------------------------------------------------------------
def login(username: str, password: str) -> dict:
    return _request("POST", "/api/v1/auth/login", auth=False, data={"username": username, "password": password})


def list_users() -> list[dict]:
    return _request("GET", "/api/v1/users")["users"]


def list_roles() -> dict:
    return _request("GET", "/api/v1/roles", auth=False)


def update_user(username: str, changes: dict) -> dict:
    return _request("PATCH", f"/api/v1/users/{username}", json=changes)


def create_user(username: str, password: str, role: str, full_name: str | None = None) -> dict:
    return _request("POST", "/api/v1/users",
                    json={"username": username, "password": password, "role": role, "full_name": full_name})


# ---------------------------------------------------------------------------
# DSS & keputusan
# ---------------------------------------------------------------------------
def dss_config() -> dict:
    return _request("GET", "/api/v1/dss/config")


def dss_update_config(config: dict) -> dict:
    return _request("PUT", "/api/v1/dss/config", json=config)


def dss_rank(batch_id: str, method: str | None = None, weights: dict | None = None,
             escalation_rate: float | None = None, persist: bool = True) -> dict:
    body = {"batch_id": batch_id, "persist": persist}
    if method:
        body["method"] = method
    if weights:
        body["weights"] = weights
    if escalation_rate is not None:
        body["escalation_rate"] = escalation_rate
    return _request("POST", "/api/v1/dss/rank", timeout=LONG_TIMEOUT, json=body)


def dss_ahp(criteria: list[str], matrix: list[list[float]], save: bool = False, source: str | None = None) -> dict:
    return _request("POST", "/api/v1/dss/ahp",
                    json={"criteria": criteria, "matrix": matrix, "save": save, "source": source})


def dss_sensitivity(batch_id: str, method: str | None = None, steps: list[float] | None = None, k: int = 10) -> dict:
    body = {"batch_id": batch_id, "k": int(k)}
    if method:
        body["method"] = method
    if steps:
        body["steps"] = steps
    return _request("POST", "/api/v1/dss/sensitivity", timeout=LONG_TIMEOUT, json=body)


def dss_er_sensitivity(batch_id: str, rates: list[float], method: str | None = None) -> dict:
    body = {"batch_id": batch_id, "rates": rates}
    if method:
        body["method"] = method
    return _request("POST", "/api/v1/dss/sensitivity/escalation-rate", timeout=LONG_TIMEOUT, json=body)


def dss_runs(batch_id: str | None = None) -> list[dict]:
    return _request("GET", "/api/v1/dss/runs", params={"batch_id": batch_id} if batch_id else {})["runs"]


def dss_evaluate(run_id: str, expert_ranking: list[str], k: int = 10) -> dict:
    return _request("POST", "/api/v1/dss/evaluate", json={"run_id": run_id, "expert_ranking": expert_ranking, "k": k})


def list_decisions(batch_id: str | None = None, status: str | None = None) -> list[dict]:
    params = {k: v for k, v in {"batch_id": batch_id, "status": status}.items() if v}
    return _request("GET", "/api/v1/decisions", params=params)["decisions"]


def update_decision(decision_key: str, payload: dict) -> dict:
    return _request("PUT", f"/api/v1/decisions/{decision_key}", json=payload)


def decision_events(decision_key: str) -> list[dict]:
    return _request("GET", f"/api/v1/decisions/{decision_key}/events")["events"]


def export_decisions_xlsx(batch_id: str | None = None) -> bytes:
    return _request("GET", "/api/v1/decisions/export.xlsx", params={"batch_id": batch_id} if batch_id else {})


def decision_agreement() -> dict:
    return _request("GET", "/api/v1/decisions/agreement")


def dashboard_summary(due_soon_days: int = 7) -> dict:
    """Mengambil ringkasan dasbor DSS (angka kunci, beban kerja, tenggat, sebaran temuan)."""
    return _request("GET", "/api/v1/dashboard", params={"due_soon_days": due_soon_days})


def ingest_report_cached(scanner: str, filename: str, raw_bytes: bytes) -> dict:
    """Streamlit menjalankan ulang halaman pada setiap interaksi widget; hindari mengunggah ulang laporan yang sama."""
    import hashlib
    import streamlit as st

    key = f"ingest_{scanner}_{hashlib.sha256(raw_bytes).hexdigest()}"
    if key not in st.session_state:
        st.session_state[key] = ingest_report(scanner, filename, raw_bytes)
    return st.session_state[key]
