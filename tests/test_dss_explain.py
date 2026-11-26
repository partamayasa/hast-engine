# tests/test_dss_explain.py
"""Penjelasan skor di DSS: rantai skor, ringkasan SHAP, penanda 'Perlu diperiksa', snapshot audit, dan ekspor."""
import io
import uuid

import pandas as pd
import pytest

from backend.db.session import session_scope
from backend.dss import explain
from backend.repositories import history as history_repo

REP = {
    "key_id": "PAIR-0001", "sast_score": 6.75, "dast_score": 7.25, "base_score": 7.0, "predicted_score": 7.3,
    "is_true_positive": True, "shap_base_value": 6.23, "shap_total_pos": 0.36, "shap_total_neg": -0.07,
    "shap_predicted_score": 7.18, "absent_vocab_bias": 0.66,
    "shap_positive": "code (+0.35) | web (+0.00)",
    "shap_negative": "application (-0.02) | disclosed (-0.02) | timestamp (-0.01)",
}


def _issue(score=7.3, rep=REP):
    return {"predicted_score": score, "is_true_positive": True, "rep": rep}


def test_parse_tokens():
    assert explain.parse_tokens("code (+0.35) | web (+0.00)") == [
        {"token": "code", "value": 0.35}, {"token": "web", "value": 0.0}]
    assert explain.parse_tokens("N/A") == [] and explain.parse_tokens(None) == []


def test_score_chain_text_shows_escalation():
    e = explain.build(_issue())
    assert e["chain"]["escalation"] == 0.3
    assert e["chain_text"] == ("SAST 6.75 dan DAST 7.25 → rata-rata 7.00 → +0.30 karena terdeteksi di kedua "
                               "scanner = 7.30.")
    assert e["model_reason"].startswith("Kata yang menaikkan: code (+0.35)")


def test_weak_text_evidence_flag():
    """Kata yang hadir hanya menggeser model sebesar 0,43 (< 0,5): skor sebagian besar adalah rata-rata model.
    7,30 juga tepat 0,30 di atas batas HIGH, sehingga kedua penanda berlaku (sama seperti isu nyata)."""
    e = explain.build(_issue())
    codes = [f["code"] for f in e["review_flags"]]
    assert codes == ["NEAR_THRESHOLD", "WEAK_TEXT_EVIDENCE"] and e["needs_review"]
    strong = {**REP, "shap_total_pos": 0.51, "shap_total_neg": -1.57}
    assert explain.build(_issue(score=7.5, rep=strong))["review_flags"] == []


@pytest.mark.parametrize("score,flagged", [(6.9, True), (7.1, True), (6.6, False), (8.75, True), (4.29, True),
                                           (5.5, False)])
def test_near_threshold_flag(score, flagged):
    strong = {**REP, "shap_total_pos": 1.0, "shap_total_neg": -1.0}
    codes = [f["code"] for f in explain.build(_issue(score=score, rep=strong))["review_flags"]]
    assert ("NEAR_THRESHOLD" in codes) is flagged


def test_missing_shap_is_flagged_not_hidden():
    rep = {k: v for k, v in REP.items() if not k.startswith("shap") and k != "absent_vocab_bias"}
    e = explain.build(_issue(score=7.5, rep=rep))
    assert e["shap"] is None and [f["code"] for f in e["review_flags"]] == ["NO_EXPLANATION"]


def test_thresholds_are_configurable():
    e = explain.build(_issue(), {"min_text_evidence": 0.1, "threshold_margin": 0.0})
    assert e["review_flags"] == []


# --- API ------------------------------------------------------------------------------------------
def _auth(t):
    return {"Authorization": f"Bearer {t}"}


def _seed(client):
    batch = f"HAST-E{uuid.uuid4().hex[:6]}"
    alert = f"Timestamp Disclosure {uuid.uuid4().hex[:5]}"
    with session_scope(client.app.state.database_url) as s:
        history_repo.save_findings(s, batch, history_repo.HYBRID_SCANNER, [{
            "key_id": "PAIR-EXPL0001", "cwe_id": "CWE-497", "component": "wp-config.php | GET https://x/",
            "issue_description": "x", "predicted_cvss4_score": 7.3, "predicted_severity": "HIGH",
            "base_score": 7.0, "sast_score": 6.75, "dast_score": 7.25, "is_true_positive": True,
            "shap_base_value": 6.23, "shap_total_pos": 0.36, "shap_total_neg": -0.07, "shap_predicted_score": 7.18,
            "absent_vocab_bias": 0.66, "shap_positive": REP["shap_positive"], "shap_negative": REP["shap_negative"],
            "sast_component": "wp-config.php", "dast_component": "GET https://x/", "dast_key_id": alert}])
    return batch


def test_rank_items_carry_explanation_and_review_count(client):
    batch = _seed(client)
    run = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False}).json()
    it = run["items"][0]
    assert it["needs_review"] and it["score_explanation"]["chain"]["escalation"] == 0.3
    assert run["summary"]["needs_review"] == 1


def test_decision_audit_stores_model_context_and_export_has_reason(client, manager_token):
    batch = _seed(client)
    run = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(manager_token)).json()
    key = run["items"][0]["decision_key"]
    r = client.put(f"/api/v1/decisions/{key}", headers=_auth(manager_token),
                   json={"chosen_action": "PLAN", "reason": "Hanya stempel waktu; skor didorong kata 'code'."})
    assert r.status_code == 200
    events = client.get(f"/api/v1/decisions/{key}/events").json()["events"]
    decided = [e for e in events if e["event_type"] == "DECIDED"][-1]
    ctx = decided["model_context"]
    assert ctx["score_origin"].endswith("= 7.30.") and "code (+0.35)" in ctx["model_reason"]
    assert ctx["review_notes"] and ctx["recommended_priority"] == "P2"
    assert "model_context" not in decided["changes"]

    xlsx = client.get("/api/v1/decisions/export.xlsx", params={"batch_id": batch}, headers=_auth(manager_token))
    df = pd.read_excel(io.BytesIO(xlsx.content))
    row = df.iloc[0]
    assert "code (+0.35)" in row["Alasan Model (SHAP)"] and row["Asal Skor"].endswith("= 7.30.")
    assert str(row["Perlu Diperiksa"]).strip()


def _migration_0004():
    import importlib.util
    from backend.db.bootstrap import MIGRATIONS_DIR
    path = MIGRATIONS_DIR / "versions" / "0004_english_payload_keys.py"
    spec = importlib.util.spec_from_file_location("migration_0004", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_0004_normalises_legacy_payload_keys():
    """Fungsi normalisasi migrasi 0004 mengganti seluruh kunci lama dan idempoten."""
    m = _migration_0004()
    legacy = {"status": {"dari": "OPEN", "menjadi": "IN_PROGRESS"},
              "konteks_model": {"asal_skor": "x = 7.30.", "alasan_model": "Kata yang menaikkan: code.",
                                "perlu_dicek": ["a"], "prioritas_rekomendasi": "P2"}}
    expected = {"status": {"from": "OPEN", "to": "IN_PROGRESS"},
                "model_context": {"score_origin": "x = 7.30.", "model_reason": "Kata yang menaikkan: code.",
                                  "review_notes": ["a"], "recommended_priority": "P2"}}
    assert m.normalise_event_payload(legacy) == expected
    assert m.normalise_event_payload(expected) == expected
    run = {"items": [{"imputed": {"impact": "cwe_tidak_ada_di_lookup", "asset_criticality": "default_konfigurasi"}}]}
    assert m.normalise_run_result(run)["items"][0]["imputed"] == {"impact": "cwe_not_in_lookup",
                                                                  "asset_criticality": "config_default"}


def test_migration_0004_rewrites_stored_rows(db_url):
    """Baris jejak audit lama di basis data ditulis ulang saat migrasi 0004 dijalankan."""
    import json as _json
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text
    from backend.db.bootstrap import MIGRATIONS_DIR
    from backend.db.session import get_engine
    from backend.repositories.dss import _event_changes, _event_model_context

    engine = get_engine(db_url)
    legacy = _json.dumps({"status": {"dari": "OPEN", "menjadi": "IN_PROGRESS"},
                          "konteks_model": {"perlu_dicek": ["a"], "prioritas_rekomendasi": "P2"}})
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO dss_decisions (decision_key, cwe_id, sast_component, dast_component, status) "
                          "VALUES ('k-mig-0004', 'CWE-79', 'a', 'b', 'OPEN')"))
        decision_id = conn.execute(text("SELECT id FROM dss_decisions WHERE decision_key = 'k-mig-0004'")).scalar()
        conn.execute(text("INSERT INTO dss_decision_events (decision_id, event_type, payload_json) "
                          "VALUES (:d, 'DECIDED', :p)"), {"d": decision_id, "p": legacy})
        cfg = Config()
        cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
        cfg.attributes["database_url"] = db_url
        cfg.attributes["connection"] = conn
        command.stamp(cfg, "0003_issue_decisions")
        command.upgrade(cfg, "head")
        stored = conn.execute(text("SELECT payload_json FROM dss_decision_events WHERE decision_id = :d"),
                              {"d": decision_id}).scalar()
    assert "konteks_model" not in stored and "dari" not in stored
    assert _event_changes(stored) == {"status": {"from": "OPEN", "to": "IN_PROGRESS"}}
    assert _event_model_context(stored) == {"review_notes": ["a"], "recommended_priority": "P2"}


def test_recommended_event_stores_model_context(client, analyst_token):
    """Baris "Rekomendasi sistem" menyimpan penjelasan model saat rekomendasi pertama kali diberikan."""
    from tests.test_dss_api import _auth, _pair, _seed_pairs
    batch = _seed_pairs(client, [_pair(1, "CWE-79", "XSS (recommended context test)", 7.5)])
    item = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token)).json()["items"][0]
    events = client.get(f"/api/v1/decisions/{item['decision_key']}/events").json()["events"]
    rec = next(e for e in events if e["event_type"] == "RECOMMENDED")
    ctx = rec["model_context"]
    assert ctx and ctx["score_origin"] == item["score_explanation"]["chain_text"]
    assert ctx["recommended_priority"] == item["recommendation"]["priority"] and ctx["run_id"] == rec["run_id"]
    assert "model_context" not in (rec["changes"] or {})


def test_migration_0005_backfills_recommended_context(db_url):
    """Peristiwa RECOMMENDED lama tanpa konteks diisi dari run DSS yang menghasilkannya."""
    import json as _json
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import text
    from backend.db.bootstrap import MIGRATIONS_DIR
    from backend.db.session import get_engine
    from backend.repositories.dss import _event_model_context

    engine = get_engine(db_url)
    run = {"items": [{"decision_key": "k-mig-0005", "recommendation": {"priority": "P2"},
                      "score_explanation": {"chain_text": "SAST 7.00 → 7.30.", "model_reason": "Kata: xss.",
                                            "review_flags": [{"text": "Dekat batas HIGH."}]}}]}
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO dss_runs (run_id, batch_id, method, weights_json, criteria_json, "
                          "alternatives_count, result_json) VALUES ('run-0005', 'HAST-0005', 'TOPSIS', '{}', '[]', 1, :r)"),
                     {"r": _json.dumps(run)})
        conn.execute(text("INSERT INTO dss_decisions (decision_key, cwe_id, sast_component, dast_component, status) "
                          "VALUES ('k-mig-0005', 'CWE-79', 'a', 'b', 'OPEN')"))
        decision_id = conn.execute(text("SELECT id FROM dss_decisions WHERE decision_key = 'k-mig-0005'")).scalar()
        conn.execute(text("INSERT INTO dss_decision_events (decision_id, event_type, payload_json, run_id) "
                          "VALUES (:d, 'RECOMMENDED', :p, 'run-0005')"),
                     {"d": decision_id, "p": _json.dumps({"rank": 1, "preference": 0.8, "rule_id": "R3"})})
        cfg = Config()
        cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
        cfg.attributes["database_url"] = db_url
        cfg.attributes["connection"] = conn
        command.stamp(cfg, "0004_english_payload_keys")
        command.upgrade(cfg, "head")
        command.stamp(cfg, "0004_english_payload_keys")
        command.upgrade(cfg, "head")  # dijalankan dua kali: idempoten
        stored = conn.execute(text("SELECT payload_json FROM dss_decision_events WHERE decision_id = :d"),
                              {"d": decision_id}).scalar()
    assert _json.loads(stored)["rank"] == 1
    assert _event_model_context(stored) == {"score_origin": "SAST 7.00 → 7.30.", "model_reason": "Kata: xss.",
                                            "review_notes": ["Dekat batas HIGH."], "recommended_priority": "P2",
                                            "run_id": "run-0005"}


def test_shap_not_computed_is_reported_as_missing_not_as_zero():
    """save_findings mengisi 0 bila SHAP belum dihitung; nilai itu bukan penjelasan model."""
    from backend.dss.explain import shap_summary
    rep = {"shap_base_value": 0.0, "shap_total_pos": 0.0, "shap_total_neg": 0.0, "shap_predicted_score": 6.8,
           "shap_positive": "N/A", "shap_negative": "N/A"}
    assert shap_summary(rep) is None
