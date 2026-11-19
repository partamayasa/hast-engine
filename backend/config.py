# backend/config.py
# Fungsi bantu konfigurasi lama (API publik dipertahankan untuk tools/tes). Jalur berkas kini berasal dari
# backend.core.settings sehingga dapat dialihkan dengan variabel lingkungan HAST_*.
import os
import json

from backend.core.settings import ROOT_DIR as _ROOT, get_settings

_S = get_settings()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = str(_ROOT)

EXCLUDED_PATH = str(_S.excluded_domains_path)
AI_CONFIG_PATH = str(_S.ai_config_path)
FRONTEND_CONFIG_PATH = str(_S.frontend_config_path)
SYSTEM_SUMMARY_PATH = str(_S.system_summary_path)

RF_MODEL_PATH = str(_S.rf_model_path)
TFIDF_PATH = str(_S.tfidf_path)


def load_ai_config() -> dict:
    if not os.path.exists(AI_CONFIG_PATH):
        raise FileNotFoundError(f"Konfigurasi AI tidak ditemukan di {AI_CONFIG_PATH}")
    with open(AI_CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_unprocessing_domains() -> list:
    if not os.path.exists(EXCLUDED_PATH):
        # Kembalikan daftar kosong bila berkas domain pengecualian belum dikonfigurasi
        return []
    with open(EXCLUDED_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
        return data.get("unprocessing_domains", [])


def load_hybrid_escalation_rate() -> float:
    # Ambil escalation rate kerentanan secara dinamis dari konfigurasi mesin AI
    try:
        ai_config = load_ai_config()
        return float(ai_config.get("escalation_rate", 0.15))
    except Exception:
        # Kembalikan laju bawaan cadangan bila pengambilan gagal
        return 0.15


def load_active_model_name() -> str:
    # Ambil nama algoritma model aktif dari konfigurasi mesin AI
    try:
        ai_config = load_ai_config()
        return str(ai_config.get("active_model", "Random Forest"))
    except Exception:
        # Kembalikan nama model usulan bawaan sebagai cadangan bila gagal
        return "Random Forest"


def calculate_severity(score: float) -> str:
    if score <= 0.0:
        return 'NONE'
    elif score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    elif score >= 0.1:
        return 'LOW'
    else:
        return 'NONE'


def load_frontend_shared_config():
    # Baca berkas konfigurasi bersama di direktori frontend secara aman
    if os.path.exists(FRONTEND_CONFIG_PATH):
        try:
            with open(FRONTEND_CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def detect_live_dataset_timestamp():
    # 1. Timpa dengan variabel lingkungan bila tersedia
    env_ts = os.getenv("DATASET_TIMESTAMP")
    if env_ts:
        return env_ts.strip().split("T")[0]

    # 2. Periksa berkas JSON snapshot NVDCVE mentah terbaru (diurutkan terbalik agar tahun terbaru diperiksa lebih dulu)
    nvd_folder = os.path.join(ROOT_DIR, "ai-model", "data", "nvdcve")
    if os.path.isdir(nvd_folder):
        json_files = sorted([f for f in os.listdir(nvd_folder) if f.startswith("nvdcve-2.0-") and f.endswith(".json")], reverse=True)
        for fname in json_files:
            fpath = os.path.join(nvd_folder, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f_nvd:
                    for _ in range(50):
                        line = f_nvd.readline()
                        if not line:
                            break
                        if '"timestamp"' in line:
                            parts = line.split('"timestamp"')
                            if len(parts) > 1 and '"' in parts[1]:
                                raw_val = parts[1].split('"')[1].strip()
                                return raw_val.split("T")[0]
            except Exception:
                pass

    # 3. Periksa waktu modifikasi cve_cvss4_dataset.csv
    dataset_csv = os.path.join(ROOT_DIR, "ai-model", "data", "cve_cvss4_dataset.csv")
    if os.path.exists(dataset_csv):
        try:
            import datetime
            mtime = os.path.getmtime(dataset_csv)
            return datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")
        except Exception:
            pass

    return None


def load_backend_metadata():
    # Ekstrak parameter metadata aplikasi dari konfigurasi frontend bersama
    config_data = load_frontend_shared_config()
    detected_ts = detect_live_dataset_timestamp()
    configured_ts = config_data.get("dataset_timestamp")

    if detected_ts and configured_ts and configured_ts != "N/A":
        final_ts = max(detected_ts, configured_ts)
    else:
        final_ts = detected_ts or configured_ts or "2026-10-13"

    return {
        "title": config_data.get("api_title", "N/A"),
        "description": config_data.get("api_description", "N/A"),
        "version": config_data.get("app_version", "N/A"),
        "dataset_timestamp": final_ts
    }
