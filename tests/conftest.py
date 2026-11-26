# tests/conftest.py
import atexit
import os
import shutil
import sys
import tempfile

import pandas as pd
import pytest
from fastapi.testclient import TestClient

# Pastikan direktori akar proyek ada di sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.core.settings import get_settings  # noqa: E402
from backend.db.bootstrap import init_database  # noqa: E402
from backend.db.session import dispose_engine, session_scope, sqlite_url_for  # noqa: E402
from backend.main import create_app  # noqa: E402

MODEL_AVAILABLE = get_settings().rf_model_path.exists() and get_settings().tfidf_path.exists()

# Tes memakai salinan templat dss_config.sample.json di folder sementara: hasilnya tidak bergantung pada
# dss_config.json lokal (di-ignore git, tidak ada di CI), dan tes yang menyimpan konfigurasi tidak menimpanya.
_DSS_CONFIG_DIR = tempfile.mkdtemp(prefix="hast_test_dss_config_")
_dss_config_copy = os.path.join(_DSS_CONFIG_DIR, "dss_config.json")
shutil.copyfile(get_settings().dss_config_sample_path, _dss_config_copy)
get_settings().dss_config_path = type(get_settings().dss_config_path)(_dss_config_copy)
atexit.register(shutil.rmtree, _DSS_CONFIG_DIR, ignore_errors=True)
requires_model = pytest.mark.skipif(not MODEL_AVAILABLE, reason="Artefak model .pkl tidak tersedia (di-ignore git).")


def pytest_collection_modifyitems(config, items):
    """Melewati tes bertanda `requires_model` bila artefak model (di-ignore git) tidak tersedia (mis. di CI)."""
    for item in items:
        if "requires_model" in item.keywords and not MODEL_AVAILABLE:
            item.add_marker(pytest.mark.skip(reason="Artefak model .pkl tidak tersedia (di-ignore git)."))


def _new_temp_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_database(sqlite_url_for(path), force=True)
    return path


def _remove_db(path: str) -> None:
    dispose_engine(sqlite_url_for(path))
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


@pytest.fixture(scope="session")
def session_db_path():
    path = _new_temp_db()
    yield path
    _remove_db(path)


@pytest.fixture(scope="session")
def client(session_db_path):
    """TestClient pada basis data sementara yang terisolasi (tidak pernah memakai database.db riset)."""
    app = create_app(database_url=sqlite_url_for(session_db_path), load_models=MODEL_AVAILABLE)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def temp_db_path():
    """Basis data SQLite sementara yang sudah dimigrasi untuk isolasi tes."""
    path = _new_temp_db()
    yield path
    _remove_db(path)


@pytest.fixture
def db_url(temp_db_path):
    return sqlite_url_for(temp_db_path)


@pytest.fixture
def save_rows(db_url):
    """Menyimpan DataFrame/record ke scan_history melalui repositori backend."""
    from backend.repositories import history as history_repo

    def _save(batch_id, scanner_type, data, execution_duration=None):
        records = data.to_dict("records") if isinstance(data, pd.DataFrame) else list(data)
        with session_scope(db_url) as s:
            return history_repo.save_findings(s, batch_id, scanner_type, records, execution_duration)
    return _save


@pytest.fixture
def manager_token(client):
    """Membuat (sekali) akun manajer di basis data sesi dan mengembalikan bearer token."""
    from backend.repositories import users as users_repo

    url = client.app.state.database_url
    with session_scope(url) as s:
        if users_repo.get_by_username(s, "manajer_uji") is None:
            users_repo.create_user(s, "manajer_uji", "rahasia-uji-123", role="manager")
    r = client.post("/api/v1/auth/login", data={"username": "manajer_uji", "password": "rahasia-uji-123"})
    return r.json()["access_token"]


@pytest.fixture
def token_for(client):
    """token_for("developer") -> bearer token akun uji dengan peran tersebut (dibuat sekali per DB sesi)."""
    from backend.repositories import users as users_repo

    def _token(role: str) -> str:
        name = f"uji_{role}"
        with session_scope(client.app.state.database_url) as s:
            if users_repo.get_by_username(s, name) is None:
                users_repo.create_user(s, name, "rahasia-uji-123", role=role)
        r = client.post("/api/v1/auth/login", data={"username": name, "password": "rahasia-uji-123"})
        return r.json()["access_token"]
    return _token


@pytest.fixture
def analyst_token(client):
    from backend.repositories import users as users_repo

    url = client.app.state.database_url
    with session_scope(url) as s:
        if users_repo.get_by_username(s, "analis_uji") is None:
            users_repo.create_user(s, "analis_uji", "rahasia-uji-123", role="analyst")
    r = client.post("/api/v1/auth/login", data={"username": "analis_uji", "password": "rahasia-uji-123"})
    return r.json()["access_token"]


@pytest.fixture
def sample_vulnerability_payload():
    """Fixture payload temuan kerentanan standar untuk endpoint /predict."""
    return {
        "scanner_type": "SonarQube",
        "description": "SQL Injection vulnerability in login authentication query via username parameter.",
        "component": "auth_controller.py",
        "issue_type": "VULNERABILITY",
        "has_cwe_tag": True,
        "target_scope_domain": "Authentication"
    }


@pytest.fixture
def sample_hybrid_payload():
    """Fixture payload standar untuk endpoint /predict/hybrid."""
    return {
        "sast_description": "SQL injection detected in UserDAO.java executeQuery on line 42.",
        "dast_description": "Time-based blind SQL injection detected on parameter 'user' via POST /api/login.",
        "cwe_id": "CWE-89",
        "sast_component": "UserDAO.java",
        "dast_component": "/api/login"
    }
