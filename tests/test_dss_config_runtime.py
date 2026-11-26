# tests/test_dss_config_runtime.py
"""dss_config.json wajib ada saat runtime; dss_config.sample.json hanya templat dan tidak dipakai sebagai cadangan."""
import pytest
from fastapi.testclient import TestClient

from backend.core.settings import get_settings
from backend.dss import config as dss_config
from backend.main import create_app


@pytest.fixture
def missing_config(tmp_path, monkeypatch):
    """Mengarahkan jalur runtime ke berkas yang tidak ada; templat sampel tetap ada di tempatnya."""
    settings = get_settings()
    assert settings.dss_config_sample_path.exists()
    monkeypatch.setattr(settings, "dss_config_path", tmp_path / "dss_config.json")
    return settings


def test_load_does_not_fall_back_to_sample(missing_config):
    with pytest.raises(dss_config.DssConfigMissingError) as e:
        dss_config.load_dss_config()
    msg = str(e.value)
    assert "dss_config.json" in msg and "cp " in msg and "dss_config.sample.json" in msg


def test_require_reports_invalid_config(tmp_path, monkeypatch):
    bad = tmp_path / "dss_config.json"
    bad.write_text('{"method": "TOPSIS", "criteria": []}', encoding="utf-8")
    monkeypatch.setattr(get_settings(), "dss_config_path", bad)
    with pytest.raises(RuntimeError, match="tidak valid"):
        dss_config.require_dss_config()


def test_backend_refuses_to_start_without_config(missing_config, tmp_path):
    app = create_app(database_url=f"sqlite:///{(tmp_path / 'x.db').as_posix()}", load_models=False)
    with pytest.raises(dss_config.DssConfigMissingError):
        with TestClient(app):
            pass


def test_runtime_config_reports_its_own_file():
    cfg = dss_config.load_dss_config()
    assert cfg["_source_file"] == "dss_config.json"
