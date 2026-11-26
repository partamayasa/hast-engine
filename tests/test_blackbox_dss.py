# tests/test_blackbox_dss.py
"""Kasus uji Black-Box lapisan DSS (modul A, D sampai H) dijalankan lewat harness yang sama dengan halaman QA."""
import pytest

from frontend.components import blackbox_dss


@pytest.fixture(scope="module")
def results():
    return {row["ID Kasus"]: row for row in blackbox_dss.run_dss_cases()}


def test_case_ids_unique_and_modules_valid():
    ids = [c.case_id for c in blackbox_dss.CASES]
    assert len(ids) == len(set(ids))
    assert {c.module for c in blackbox_dss.CASES} <= set(blackbox_dss.MODULE_LABELS)


@pytest.mark.parametrize("case_id", [c.case_id for c in blackbox_dss.CASES])
def test_dss_blackbox_case_passes(results, case_id):
    row = results[case_id]
    assert row["Status"] == "PASS", row["Hasil Aktual"]


def test_harness_restores_config_path():
    from backend.core.settings import get_settings
    before = get_settings().dss_config_path
    blackbox_dss.run_dss_cases()
    assert get_settings().dss_config_path == before
