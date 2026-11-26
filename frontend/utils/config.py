# frontend/utils/config.py
import os
import json
import requests
import streamlit as st

# Tentukan lokasi absolut direktori frontend
UTILS_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(UTILS_DIR, ".."))
ROOT_DIR = os.path.abspath(os.path.join(FRONTEND_DIR, ".."))
CONFIG_PATH = os.path.join(FRONTEND_DIR, "config", "app_config.json")

def load_env_file(force_reload: bool = False):
    """Membaca variabel lingkungan dari berkas .env bila tersedia."""
    env_file = os.path.join(ROOT_DIR, ".env")
    if os.path.exists(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if force_reload or k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass

load_env_file()

DEFAULT_SONAR_HOST = "http://localhost:9000"
SONAR_HOST_URL = os.getenv("SONAR_HOST_URL", DEFAULT_SONAR_HOST).rstrip("/")
SONAR_TOKEN = os.getenv("SONAR_TOKEN", "")


@st.cache_data(ttl=60)
def get_sonar_settings() -> tuple[str, str, str]:
    """Mengambil konfigurasi SonarQube terkini dari variabel lingkungan / berkas .env."""
    load_env_file()
    host = os.getenv("SONAR_HOST_URL", DEFAULT_SONAR_HOST).strip().rstrip("/")
    token = os.getenv("SONAR_TOKEN", "").strip()
    project_key = os.getenv("SONAR_PROJECT_KEY", "").strip()
    return host, token, project_key


# v2: basis data dimiliki backend; UI tidak memiliki DB_PATH.
SAMPLE_REPORTS_DIR = os.path.join(ROOT_DIR, "sample-reports")
SAMPLE_SQ_PATH = os.path.join(SAMPLE_REPORTS_DIR, "SonarQube_Report.json")
SAMPLE_ZAP_PATH = os.path.join(SAMPLE_REPORTS_DIR, "OWASP_ZAP_Report.json")
# URL dasar universal API backend (bawaan: http://127.0.0.1:8000)
DEFAULT_API_URL = "http://127.0.0.1:8000"
API_BASE_URL = os.getenv("API_BASE_URL", DEFAULT_API_URL).rstrip("/")
# URL dasar API untuk tautan di browser; bila kosong atau tidak diisi, memakai API_BASE_URL.
PUBLIC_API_BASE_URL = (os.getenv("PUBLIC_API_BASE_URL") or API_BASE_URL).rstrip("/")
SAMPLE_SQ_URL = f"{PUBLIC_API_BASE_URL}/sample-reports/SonarQube_Report.json"
SAMPLE_ZAP_URL = f"{PUBLIC_API_BASE_URL}/sample-reports/OWASP_ZAP_Report.json"



def load_app_config():
    """Membaca konfigurasi aplikasi dari app_config.json secara aman."""
    default_config = {
        "api_title": "N/A",
        "api_description": "N/A",
        "app_version": "N/A",
        "app_subtitle": "N/A",
        "dataset_timestamp": "N/A"
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                config = json.load(f)
                for key, default_val in default_config.items():
                    if key not in config:
                        config[key] = default_val
                return config
        except Exception:
            return default_config
    return default_config


OFFLINE_STATUS = ("N/A", "N/A", "N/A", "N/A", "N/A", False, "N/A")


def get_application_version():
    """
    Mengembalikan status operasional dan versi aplikasi dari backend FastAPI.

    Hanya hasil online yang disimpan di cache. Hasil offline tidak di-cache agar halaman pulih begitu backend
    aktif, misalnya ketika frontend dinyalakan beberapa detik sebelum backend selesai memuat model.
    """
    status = _fetch_application_version()
    if not status[5]:
        _fetch_application_version.clear()
    return status


@st.cache_data(ttl=60)
def _fetch_application_version():
    """Menghubungi backend dan mengembalikan tuple status aplikasi (dipakai oleh get_application_version)."""
    urls_to_try = [API_BASE_URL]
    if "127.0.0.1" not in API_BASE_URL:
        urls_to_try.insert(0, "http://127.0.0.1:8000")
    if "localhost" not in API_BASE_URL:
        urls_to_try.append("http://localhost:8000")

    for url in urls_to_try:
        try:
            response = requests.get(f"{url}/", timeout=3)
            if response.status_code == 200:
                res_json = response.json()
                is_online = (res_json.get("status") == "online")
                er_val = res_json.get("escalation_rate", 0.15)
                er_percentage = f"{int(er_val * 100)}%"
                dataset_ts = res_json.get("dataset_timestamp")
                if not dataset_ts or dataset_ts == "N/A":
                    try:
                        sum_res = requests.get(f"{url}/system_summary.json", timeout=2)
                        if sum_res.status_code == 200:
                            dataset_ts = sum_res.json().get("dataset_timestamp", "N/A")
                    except Exception:
                        dataset_ts = "N/A"
                return (
                    res_json.get("title", "N/A"),
                    res_json.get("version", "N/A"),
                    res_json.get("description", "N/A"),
                    er_percentage,
                    res_json.get("active_model", "Random Forest"),
                    is_online,
                    dataset_ts or "N/A"
                )
        except Exception:
            continue

    return OFFLINE_STATUS


def get_active_model():
    """Mengambil model aktif secara dinamis dari API backend atau konfigurasi lokal."""
    urls_to_try = [API_BASE_URL]
    if "127.0.0.1" not in API_BASE_URL:
        urls_to_try.insert(0, "http://127.0.0.1:8000")
    if "localhost" not in API_BASE_URL:
        urls_to_try.append("http://localhost:8000")

    for url in urls_to_try:
        try:
            response = requests.get(f"{url}/", timeout=3)
            if response.status_code == 200:
                model = response.json().get("active_model")
                if model:
                    return model
        except Exception:
            continue

    config_data = load_app_config()
    return config_data.get("active_model", "Random Forest")
