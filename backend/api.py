# backend/api.py
"""
Shim kompatibilitas: perintah `uvicorn backend.api:app` tetap berlaku.

Aplikasi kini berada di backend/main.py (factory + lifespan) dengan router di
backend/routers/v1/.
"""
from backend.main import app, create_app  # noqa: F401
