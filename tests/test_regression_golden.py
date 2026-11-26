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
from backend.core.settings import ROOT_DIR
from backend.db.session import session_scope
from backend.repositories import history as history_repo
from backend.services import scoring
from backend.services.parsers.reports import decode_report, parse_sonarqube, parse_zap

GOLDEN = os.path.join(ROOT_DIR, "tests", "golden", "baseline_predictions.json")
# Laporan yang menghasilkan baseline disimpan terpisah, sehingga sample-reports boleh diganti tanpa mengubah baseline.
GOLDEN_REPORTS = ROOT_DIR / "tests" / "golden" / "sample-reports"

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


# Penyimpangan yang disengaja dari v1 (Fase 30): aturan aksesibilitas Web:S6819 (CODE_SMELL, metadata resmi SonarQube
# tanpa CWE) dulu dipetakan keliru ke CWE-693, sehingga lolos parser dan membentuk pasangan hybrid. Temuan aturan ini
# kini tidak lolos parser. Baseline v1 tetap dibekukan; temuan S6819 dikeluarkan dari pembanding, sedangkan skor seluruh
# temuan dan pasangan lainnya harus tetap identik.
EXCLUDED_RULES = {"Web:S6819"}


def _excluded_sonar_issues() -> tuple[set, set]:
    """Mengembalikan (kunci isu, komponen) temuan SonarQube sampel yang aturannya dikecualikan."""
    with open(GOLDEN_REPORTS / "SonarQube_Report.json", encoding="utf-8-sig") as f:
        data = json.load(f)
    issues = [i for i in data.get("issues", []) if i.get("rule") in EXCLUDED_RULES]
    return {i.get("key") for i in issues}, {i.get("component") for i in issues}


def _slim(rows):
    return [{k: r[k] for k in ("key_id", "cwe_id", "component", "predicted_cvss4_score", "predicted_severity")}
            for r in rows]


@pytest.fixture(scope="module")
def scored(models):
    sast = scoring.score_records("SAST", parse_sonarqube(_read(GOLDEN_REPORTS / "SonarQube_Report.json")))
    dast = scoring.score_records("DAST", parse_zap(_read(GOLDEN_REPORTS / "OWASP_ZAP_Report.json"),
                                                  load_unprocessing_domains()))
    return sast, dast


def test_golden_config_unchanged(golden):
    """Escalation rate dan domain pengecualian yang dipakai baseline masih berlaku."""
    assert load_hybrid_escalation_rate() == golden["escalation_rate"]
    assert load_unprocessing_domains() == golden["excluded_domains"]


def test_golden_sast_scores_identical(golden, scored):
    excluded_keys, _ = _excluded_sonar_issues()
    expected = [r for r in golden["sast"] if r["key_id"] not in excluded_keys]
    assert len(excluded_keys) == len(golden["sast"]) - len(expected) == 37
    assert _slim(scored[0]) == expected


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
    _, excluded_components = _excluded_sonar_issues()
    expected = {key(r): r for r in golden["hybrid_pairs"]
                if not (r["cwe_id"] == "CWE-693" and key(r)[1] in excluded_components)}
    assert len(expected) < len(golden["hybrid_pairs"])
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
