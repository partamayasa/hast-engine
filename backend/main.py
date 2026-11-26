# backend/main.py
"""Factory aplikasi FastAPI untuk Sistem Pendukung Keputusan HAST."""
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend import model_loader
from backend.config import load_backend_metadata
from backend.core.settings import get_settings
from backend.db.bootstrap import init_database
from backend.dss.config import require_dss_config


def create_app(database_url: str | None = None, load_models: bool = True) -> FastAPI:
    settings = get_settings()
    db_url = database_url or settings.database_url

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Gagal start lebih awal bila dss_config.json tidak ada: templat sampel tidak dipakai sebagai cadangan.
        require_dss_config()
        init_database(db_url)
        if load_models:
            try:
                model_loader.init_models()
                print("-> [Backend Startup]: Sukses memuat seluruh aset biner model.")
            except Exception as e:
                print(f"-> [CRITICAL ERROR STARTUP]: Inisialisasi model gagal. Detail: {e}")
        if settings.environment == "production" and not settings.model_fields_set.intersection({"jwt_secret"}):
            print("-> [PERINGATAN KEAMANAN]: HAST_JWT_SECRET tidak diatur; token login akan hangus saat restart.")
        yield

    meta = load_backend_metadata()
    app = FastAPI(title=meta["title"], description=meta["description"], version=meta["version"], lifespan=lifespan)
    app.state.database_url = db_url

    from backend.routers.v1 import auth, dashboard, decisions, dss, findings, research, scoring, system

    for module in (system, scoring, findings, research, auth, dss, decisions, dashboard):
        app.include_router(module.router)
    return app


app = create_app()
