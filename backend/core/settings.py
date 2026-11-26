# backend/core/settings.py
"""
Pengaturan runtime terpusat untuk backend DSS HAST.

Seluruh jalur berkas dan rahasia ditentukan di sini (pydantic-settings, prefiks variabel lingkungan ``HAST_``).
Berkas konfigurasi JSON tetap berada di lokasi historisnya agar pipeline pelatihan
(ai-model/training/pipeline_engine.py) tetap berjalan tanpa perubahan.
"""
import os
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HAST_",
        env_file=str(ROOT_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Lingkungan ---------------------------------------------------------
    environment: str = Field("development", description="development | production | test")

    # --- Basis data --------------------------------------------------------
    database_url: str = Field(
        default=f"sqlite:///{(ROOT_DIR / 'database' / 'database.db').as_posix()}",
        description="URL SQLAlchemy. SQLite (bawaan) atau postgresql+psycopg://...",
    )

    # --- Berkas konfigurasi (lokasi historis) ------------------------------
    ai_config_path: Path = ROOT_DIR / "ai-model" / "config" / "ai_config.json"
    excluded_domains_path: Path = ROOT_DIR / "backend" / "config" / "excluded_domains.json"
    system_summary_path: Path = ROOT_DIR / "backend" / "config" / "system_summary.json"
    dss_config_path: Path = ROOT_DIR / "backend" / "config" / "dss_config.json"
    dss_config_sample_path: Path = ROOT_DIR / "backend" / "config" / "dss_config.sample.json"
    frontend_config_path: Path = ROOT_DIR / "frontend" / "config" / "app_config.json"
    sonar_rules_cache_path: Path = ROOT_DIR / "frontend" / "config" / "sonar_rules_cache.json"

    # --- Artefak model dan data riset --------------------------------------
    rf_model_path: Path = ROOT_DIR / "ai-model" / "artifacts" / "model_random_forest.pkl"
    tfidf_path: Path = ROOT_DIR / "ai-model" / "artifacts" / "tfidf_vectorizer.pkl"
    cwe_lookup_path: Path = ROOT_DIR / "ai-model" / "data" / "cwe_cvss4_lookup_table.csv"
    sample_reports_dir: Path = ROOT_DIR / "sample-reports"

    # --- Autentikasi ------------------------------------------------------
    jwt_secret: str = Field(default_factory=lambda: os.getenv("HAST_JWT_SECRET") or secrets.token_urlsafe(48))
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 8 * 60
    admin_username: str = ""
    admin_password: str = ""

    # --- Batas unggahan ---------------------------------------------------
    max_upload_mb: int = 50

    # --- API SonarQube (tetap kompatibel dengan nama variabel historis) ----
    sonar_host_url: str = Field(default_factory=lambda: os.getenv("SONAR_HOST_URL", "http://localhost:9000"))
    sonar_token: str = Field(default_factory=lambda: os.getenv("SONAR_TOKEN", ""))

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()
