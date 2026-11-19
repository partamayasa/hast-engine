# tests/test_regression_golden.py
"""
Regresi emas: pipeline v2 hasil refaktor (parser backend -> skoring batch -> repositori
-> korelasi) harus mereproduksi skor v1.0.0-tesis secara persis.

Berkas baseline: tests/golden/baseline_predictions.json, dihasilkan oleh logika v1 yang dibekukan di
tools/regression/generate_baseline.py. Setiap perbedaan di sini berarti ada angka tesis yang berubah.
"""
import json
import os

import pytest

from backend.config import load_hybrid_escalation_rate, load_unprocessing_domains
from backend.core.settings import ROOT_DIR, get_settings
from backend.db.session import session_scope
from backend.repositories import history as history_repo
from backend.services import scoring
from backend.services.parsers.reports import decode_report, parse_sonarqube, parse_zap

GOLDEN = os.path.join(ROOT_DIR, "tests", "golden", "baseline_predictions.json")

pytestmark = [pytest.mark.requires_model, pytest.mark.slow]


@pytest.fixture(scope="module")
def golden():
    if not os.path.exists(GOLDEN):
        pytest.skip("Baseline emas belum dibuat (jalankan tools/regression/generate_baseline.py).")
    with open(GOLDEN, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def models():
    from backend import model_loader
    model_loader.init_models()


def _read(path):
    with open(path, "rb") as f:
        return decode_report(f.read())


def _slim(rows):
    return [{k: r[k] for k in ("key_id", "cwe_id", "component", "predicted_cvss4_score", "predicted_severity")}
            for r in rows]


@pytest.fixture(scope="module")
def scored(models):
    s = get_settings()
    sast = scoring.score_records("SAST", parse_sonarqube(_read(s.sample_reports_dir / "SonarQube_Report.json")))
    dast = scoring.score_records("DAST", parse_zap(_read(s.sample_reports_dir / "OWASP_ZAP_Report.json"),
                                                  load_unprocessing_domains()))
    return sast, dast


def test_golden_config_unchanged(golden):
    """Escalation rate dan domain pengecualian yang dipakai baseline masih berlaku."""
    assert load_hybrid_escalation_rate() == golden["escalation_rate"]
    assert load_unprocessing_domains() == golden["excluded_domains"]


def test_golden_sast_scores_identical(golden, scored):
    assert _slim(scored[0]) == golden["sast"]


def test_golden_dast_scores_identical(golden, scored):
    assert _slim(scored[1]) == golden["dast"]


def test_golden_hybrid_pairs_identical(golden, scored, db_url):
    """Simpan kedua batch, korelasikan dari basis data (seperti UI), lalu bandingkan setiap pasangan."""
    sast, dast = scored
    with session_scope(db_url) as s:
        history_repo.save_findings(s, "SAST-GOLD", history_repo.SAST_SCANNER, sast)
        history_repo.save_findings(s, "DAST-GOLD", history_repo.DAST_SCANNER, dast)
    with session_scope(db_url) as s:
        pairs = scoring.preview_pairs(history_repo.list_batch(s, "SAST-GOLD"), history_repo.list_batch(s, "DAST-GOLD"))
    records = scoring.score_pairs(pairs)

    def key(r):
        return (r["cwe_id"], r["sast_component"] if "sast_component" in r else r["component_sast"],
                r["dast_component"] if "dast_component" in r else r["component_dast"])

    actual = {key(r): r for r in records}
    expected = {key(r): r for r in golden["hybrid_pairs"]}
    assert set(actual) == set(expected)
    for k, exp in expected.items():
        got = actual[k]
        assert got["sast_score"] == exp["sast_score"], k
        assert got["dast_score"] == exp["dast_score"], k
        assert got["base_score"] == exp["base_score"], k
        assert got["predicted_cvss4_score"] == exp["hybrid_score"], k
        assert got["predicted_severity"] == exp["severity"], k
        assert got["is_true_positive"] == exp["is_verified_true_positive"], k
        assert got["shap_base_value"] == exp["shap_base_value"], k
        assert got["shap_predicted_score"] == exp["shap_predicted_score"], k
