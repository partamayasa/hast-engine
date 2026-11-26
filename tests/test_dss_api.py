# tests/test_dss_api.py
"""Endpoint DSS, keputusan, dan autentikasi pada basis data terisolasi (tanpa model ML: skor sudah diberikan)."""
import datetime
import uuid

import pytest

from backend.db.session import session_scope
from backend.repositories import history as history_repo


def _seed_hybrid_batch(client, n=4):
    batch = f"HAST-T{uuid.uuid4().hex[:6]}"
    records = []
    for i in range(n):
        score = [9.2, 7.4, 6.1, 4.3][i % 4]
        records.append({
            "key_id": f"PAIR-{i:08X}", "cwe_id": ["CWE-79", "CWE-89", "CWE-614", "CWE-693"][i % 4],
            "component": f"src/mod{i}.php | GET https://app.test/p{i}",
            "issue_description": f"[SAST]: issue {i}\n[DAST]: alert {i}",
            "predicted_cvss4_score": score, "predicted_severity": "CRITICAL" if score >= 9 else ("HIGH" if score >= 7 else "MEDIUM"),
            "base_score": score, "sast_score": score, "dast_score": score, "is_true_positive": i != 3,
            "sast_component": f"src/mod{i}.php", "dast_component": f"GET https://app.test/p{i}",
            "sast_key_id": f"S{i}", "dast_key_id": f"D{i}",
        })
    with session_scope(client.app.state.database_url) as s:
        history_repo.save_findings(s, batch, history_repo.HYBRID_SCANNER, records)
    return batch


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_login_rejects_wrong_password(client, analyst_token):
    r = client.post("/api/v1/auth/login", data={"username": "analis_uji", "password": "salah-sekali"})
    assert r.status_code == 401


def test_me_returns_role(client, manager_token):
    assert client.get("/api/v1/auth/me", headers=_auth(manager_token)).json()["role"] == "manager"


def test_rank_preview_is_public_and_complete(client):
    batch = _seed_hybrid_batch(client)
    r = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False})
    assert r.status_code == 200
    body = r.json()
    assert [it["rank"] for it in body["items"]] == [1, 2, 3, 4]
    assert body["persisted"] is False
    first = body["items"][0]
    assert {"preference", "criteria", "recommendation", "why", "imputed", "priority", "title", "files",
            "endpoints"} <= set(first)
    assert sum(c["weight"] for c in first["criteria"]) == pytest.approx(1.0)


def test_rank_persist_requires_login(client):
    batch = _seed_hybrid_batch(client)
    assert client.post("/api/v1/dss/rank", json={"batch_id": batch}).status_code == 401


def test_rank_rejects_non_hybrid_and_unknown_batches(client):
    with session_scope(client.app.state.database_url) as s:
        history_repo.save_findings(s, "SAST-ONLY", history_repo.SAST_SCANNER,
                                   [{"key_id": "x", "cwe_id": "CWE-79", "component": "a", "issue_description": "d",
                                     "predicted_cvss4_score": 5.0, "predicted_severity": "MEDIUM"}])
    assert client.post("/api/v1/dss/rank", json={"batch_id": "SAST-ONLY", "persist": False}).status_code == 422
    assert client.post("/api/v1/dss/rank", json={"batch_id": "TIDAK-ADA", "persist": False}).status_code == 404


def test_rank_invalid_weights_rejected(client):
    batch = _seed_hybrid_batch(client)
    r = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False, "weights": {"tidak_ada": 1}})
    assert r.status_code == 422


def test_rerank_never_overwrites_analyst_decision(client, analyst_token):
    batch = _seed_hybrid_batch(client)
    run = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token)).json()
    key = run["items"][0]["decision_key"]
    upd = client.put(f"/api/v1/decisions/{key}", headers=_auth(analyst_token),
                     json={"chosen_action": "DEFER", "status": "DEFERRED", "reason": "Menunggu rilis", "asset_criticality": 1})
    assert upd.status_code == 200 and upd.json()["decided_by"] == "analis_uji"

    run2 = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token)).json()
    dec = next(it["decision"] for it in run2["items"] if it["decision_key"] == key)
    assert dec["chosen_action"] == "DEFER" and dec["status"] == "DEFERRED" and dec["reason"] == "Menunggu rilis"
    # Masukan kekritisan dari analis dipakai oleh ranking berikutnya.
    item = next(it for it in run2["items"] if it["decision_key"] == key)
    assert next(c["value"] for c in item["criteria"] if c["key"] == "asset_criticality") == 1.0

    events = client.get(f"/api/v1/decisions/{key}/events").json()["events"]
    assert [e["event_type"] for e in events][:2] == ["RECOMMENDED", "DECIDED"]


def test_business_impact_and_effort_use_five_level_scale(client, analyst_token):
    batch = _seed_hybrid_batch(client)
    run = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token)).json()
    key = run["items"][0]["decision_key"]
    ok = client.put(f"/api/v1/decisions/{key}", headers=_auth(analyst_token),
                    json={"asset_criticality": 4, "remediation_effort": 5})
    assert ok.status_code == 200 and ok.json()["remediation_effort"] == 5
    for field in ("asset_criticality", "remediation_effort"):
        for bad in (0, 6):
            r = client.put(f"/api/v1/decisions/{key}", headers=_auth(analyst_token), json={field: bad})
            assert r.status_code == 422, (field, bad)

    run2 = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token)).json()
    item = next(it for it in run2["items"] if it["decision_key"] == key)
    assert next(c["value"] for c in item["criteria"] if c["key"] == "remediation_effort") == 5.0
    # Setiap tingkat 1-5 memiliki label, termasuk nilai 4 yang sebelumnya tidak berlabel.
    assert item["business_impact_label"] == "Tinggi" and item["effort_label"] == "Sangat besar"
    meta = client.get("/api/v1/dss/config").json()
    assert set(map(int, meta["business_impact_levels"])) == set(map(int, meta["effort_levels"])) == {1, 2, 3, 4, 5}


def test_decision_status_requiring_reason(client, analyst_token):
    batch = _seed_hybrid_batch(client)
    run = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token)).json()
    key = run["items"][1]["decision_key"]
    r = client.put(f"/api/v1/decisions/{key}", headers=_auth(analyst_token), json={"status": "FALSE_POSITIVE"})
    assert r.status_code == 422
    assert client.put(f"/api/v1/decisions/{key}", json={"status": "RESOLVED"}).status_code == 401


def test_sensitivity_and_runs(client, analyst_token):
    batch = _seed_hybrid_batch(client)
    client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token))
    sens = client.post("/api/v1/dss/sensitivity", json={"batch_id": batch}).json()
    assert sens["n_alternatives"] == 4 and len(sens["variants"]) > 0
    er = client.post("/api/v1/dss/sensitivity/escalation-rate", json={"batch_id": batch, "rates": [0.0, 0.2]}).json()
    assert [v["escalation_rate"] for v in er["variants"]] == [0.0, 0.2]
    runs = client.get("/api/v1/dss/runs", params={"batch_id": batch}).json()["runs"]
    assert len(runs) == 1 and runs[0]["created_by"] == "analis_uji"


def test_evaluate_against_expert_ranking(client, analyst_token):
    batch = _seed_hybrid_batch(client)
    run = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token)).json()
    order = [it["key_id"] for it in run["items"]]
    ev = client.post("/api/v1/dss/evaluate", headers=_auth(analyst_token),
                     json={"run_id": run["run_id"], "expert_ranking": order, "k": 2}).json()
    assert ev["dss_vs_expert"]["spearman_rho"] == pytest.approx(1.0)
    assert ev["dss_vs_expert"]["precision_at_k"] == 1.0


def test_ahp_endpoint_and_save_permissions(client, analyst_token, manager_token):
    body = {"criteria": ["hybrid_score", "true_positive", "asset_criticality"],
            "matrix": [[1, 3, 2], [1 / 3, 1, 0.5], [0.5, 2, 1]]}
    r = client.post("/api/v1/dss/ahp", json=body).json()
    assert r["is_consistent"] and sum(r["weights"].values()) == pytest.approx(1.0)
    assert client.post("/api/v1/dss/ahp", json={**body, "save": True}, headers=_auth(analyst_token)).status_code == 403
    bad = {"criteria": ["hybrid_score", "true_positive", "asset_criticality"],
           "matrix": [[1, 9, 1 / 9], [1 / 9, 1, 9], [9, 1 / 9, 1]], "save": True}
    assert client.post("/api/v1/dss/ahp", json=bad, headers=_auth(manager_token)).status_code == 422


def test_config_update_requires_manager_and_validation(client, analyst_token, manager_token):
    cfg = client.get("/api/v1/dss/config").json()
    assert client.put("/api/v1/dss/config", json=cfg, headers=_auth(analyst_token)).status_code == 403
    broken = {**cfg, "recommendation_rules": cfg["recommendation_rules"][:-1]}
    assert client.put("/api/v1/dss/config", json=broken, headers=_auth(manager_token)).status_code == 422


def test_delete_batch_requires_login(client, analyst_token, manager_token):
    batch = _seed_hybrid_batch(client)
    assert client.delete(f"/api/v1/batches/{batch}").status_code == 401
    # RBAC v2.1: penghapusan riwayat hanya untuk Manajer Keamanan / Administrator.
    assert client.delete(f"/api/v1/batches/{batch}", headers=_auth(analyst_token)).status_code == 403
    assert client.delete(f"/api/v1/batches/{batch}", headers=_auth(manager_token)).json()["deleted"] == 4


def test_export_xlsx(client, analyst_token):
    batch = _seed_hybrid_batch(client)
    client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token))
    r = client.get("/api/v1/decisions/export.xlsx", params={"batch_id": batch}, headers=_auth(analyst_token))
    assert r.status_code == 200 and r.content[:2] == b"PK"


def _seed_pairs(client, records):
    batch = f"HAST-T{uuid.uuid4().hex[:6]}"
    with session_scope(client.app.state.database_url) as s:
        history_repo.save_findings(s, batch, history_repo.HYBRID_SCANNER, records)
    return batch


def _pair(i, cwe, alert, score, tp=True, file=None, endpoint="GET https://app.test/"):
    sev = "CRITICAL" if score >= 9 else ("HIGH" if score >= 7 else "MEDIUM")
    file = file or f"src/f{i}.php"
    return {"key_id": f"PAIR-{i:08X}", "cwe_id": cwe, "component": f"{file} | {endpoint}",
            "issue_description": "x", "predicted_cvss4_score": score, "predicted_severity": sev,
            "base_score": score, "is_true_positive": tp, "sast_component": file, "dast_component": endpoint,
            "sast_key_id": f"S{i}", "dast_key_id": alert, "mitigation_text": f"Perbaiki {alert}"}


def test_pairs_are_grouped_into_issues(client):
    """20 pasangan dari satu alert ZAP + 1 pasangan alert lain menjadi 2 isu, dengan seluruh berkas sebagai bukti."""
    recs = [_pair(i, "CWE-693", "CSP Header Not Set", 6.67) for i in range(20)]
    recs.append(_pair(99, "CWE-614", "Cookie Without Secure Flag", 7.09))
    batch = _seed_pairs(client, recs)
    run = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False}).json()
    assert run["pairs_count"] == 21 and run["issues_count"] == 2
    csp = next(it for it in run["items"] if it["cwe_id"] == "CWE-693")
    assert len(csp["files"]) == 20 and csp["mitigation_text"] == "Perbaiki CSP Header Not Set"
    assert csp["issue_code"].startswith("ISU-")


def test_priority_never_contradicts_order(client):
    """Isu HIGH tidak pernah tercantum di bawah isu MEDIUM, seluas apa pun sebaran isu MEDIUM tersebut."""
    recs = [_pair(i, "CWE-693", "CSP Header Not Set", 6.67) for i in range(20)]
    recs.append(_pair(99, "CWE-497", "Server Leaks Information", 7.3))
    batch = _seed_pairs(client, recs)
    items = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False}).json()["items"]
    assert [it["priority"] for it in items] == ["P2", "P3"]
    assert items[0]["severity"] == "HIGH"


def test_business_impact_raises_priority_and_explanation_is_honest(client, analyst_token):
    batch = _seed_pairs(client, [_pair(1, "CWE-79", "XSS Reflected", 7.5), _pair(2, "CWE-352", "Anti-CSRF", 6.5)])
    run = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token)).json()
    xss = next(it for it in run["items"] if it["cwe_id"] == "CWE-79")
    assert xss["priority"] == "P2"
    # Dampak bisnis bawaan (belum dinilai) bernilai konstan -> tidak pernah disebut sebagai alasan.
    assert "dampak bisnisnya lebih tinggi" not in xss["why"] and "belum dinilai" in xss["why"]
    client.put(f"/api/v1/decisions/{xss['decision_key']}", headers=_auth(analyst_token),
               json={"asset_criticality": 5, "owner": "Tim Web"})
    run2 = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False}).json()
    xss2 = next(it for it in run2["items"] if it["cwe_id"] == "CWE-79")
    assert xss2["priority"] == "P1" and xss2["recommendation"]["rule_id"] == "R2"
    assert xss2["decision"]["owner"] == "Tim Web"


def test_analyst_priority_override_reorders_queue(client, analyst_token):
    # Nama alert unik: keputusan memang sengaja terbawa antarpemindaian untuk isu yang sama.
    batch = _seed_pairs(client, [_pair(1, "CWE-79", "XSS Stored (override test)", 7.5),
                                 _pair(2, "CWE-352", "Anti-CSRF (override test)", 6.5)])
    run = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token)).json()
    csrf = next(it for it in run["items"] if it["cwe_id"] == "CWE-352")
    client.put(f"/api/v1/decisions/{csrf['decision_key']}", headers=_auth(analyst_token),
               json={"chosen_action": "REMEDIATE_NOW", "status": "IN_PROGRESS"})
    items = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False}).json()["items"]
    assert items[0]["cwe_id"] == "CWE-352" and items[0]["priority"] == "P1" and items[0]["priority_overridden"]


def test_agreement_counts_follow_recommendation(client, analyst_token):
    batch = _seed_pairs(client, [_pair(1, "CWE-1004", "Cookie No HttpOnly", 6.9)])
    run = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token)).json()
    before = client.get("/api/v1/decisions/agreement").json()
    client.put(f"/api/v1/decisions/{run['items'][0]['decision_key']}", headers=_auth(analyst_token),
               json={"status": "IN_PROGRESS"})
    after = client.get("/api/v1/decisions/agreement").json()
    assert after["decided"] == before["decided"] + 1
    assert after["agreed"] == before["agreed"] + 1


def test_rank_what_if_cannot_be_persisted(client, analyst_token):
    """Simulasi what-if (bobot/ER/metode lain) tidak boleh menggantikan rekomendasi resmi yang tersimpan."""
    batch = _seed_pairs(client, [_pair(1, "CWE-79", "XSS (what-if test)", 6.5)])
    h = _auth(analyst_token)
    for extra in ({"escalation_rate": 1.0}, {"weights": {"hybrid_score": 1}}, {"method": "WP"}):
        r = client.post("/api/v1/dss/rank", json={"batch_id": batch, **extra}, headers=h)
        assert r.status_code == 422, extra
        assert client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False, **extra}).status_code == 200
    # Metode yang sama dengan konfigurasi bukan what-if.
    method = client.get("/api/v1/dss/config").json()["method"]
    assert client.post("/api/v1/dss/rank", json={"batch_id": batch, "method": method}, headers=h).status_code == 200


def test_sla_tightens_when_recommendation_escalates(client, analyst_token):
    """MEDIUM -> P3 (90 hari); setelah dampak bisnis dinaikkan -> P2 (30 hari): tenggat tersimpan ikut mengetat."""
    batch = _seed_pairs(client, [_pair(1, "CWE-352", "CSRF (sla tighten test)", 6.5)])
    h = _auth(analyst_token)
    item = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=h).json()["items"][0]
    assert item["recommendation"]["action"] == "PLAN"
    client.put(f"/api/v1/decisions/{item['decision_key']}", headers=h, json={"asset_criticality": 5})
    item2 = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=h).json()["items"][0]
    assert item2["recommendation"]["action"] == "REMEDIATE_SCHEDULED"
    assert item2["decision"]["sla_due_date"] == item2["recommendation"]["sla_due_date"]
    assert item2["decision"]["sla_due_date"] < item["decision"]["sla_due_date"]


def test_sla_set_by_analyst_is_never_overwritten(client, analyst_token):
    batch = _seed_pairs(client, [_pair(1, "CWE-352", "CSRF (sla manual test)", 6.5)])
    h = _auth(analyst_token)
    item = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=h).json()["items"][0]
    client.put(f"/api/v1/decisions/{item['decision_key']}", headers=h,
               json={"sla_due_date": "2099-01-01", "asset_criticality": 5})
    item2 = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=h).json()["items"][0]
    assert item2["recommendation"]["action"] == "REMEDIATE_SCHEDULED"
    assert item2["decision"]["sla_due_date"] == "2099-01-01"


def test_developer_form_payload_is_accepted(client, analyst_token, token_for):
    """Payload form untuk peran Pengembang hanya memuat kolom progres sehingga tidak ditolak (403)."""
    from frontend.components.page_priority import build_decision_payload
    batch = _seed_pairs(client, [_pair(1, "CWE-79", "XSS (developer form test)", 7.5)])
    item = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(analyst_token)).json()["items"][0]
    payload = build_decision_payload({"triage": False, "override": False}, status="IN_PROGRESS", note=" ",
                                     owner="", business_impact=None, effort=None, due=None, priority="IKUTI")
    assert set(payload) == {"status", "reason"}
    r = client.put(f"/api/v1/decisions/{item['decision_key']}", json=payload, headers=_auth(token_for("developer")))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "IN_PROGRESS" and r.json()["asset_criticality"] is None


def test_triage_form_keeps_business_impact_unassessed(client, analyst_token):
    """Analis yang hanya mengubah status tidak mengubah 'belum dinilai' menjadi nilai eksplisit."""
    from frontend.components.page_priority import build_decision_payload
    batch = _seed_pairs(client, [_pair(1, "CWE-79", "XSS (triage form test)", 7.5)])
    h = _auth(analyst_token)
    item = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=h).json()["items"][0]
    dec = item["decision"]
    payload = build_decision_payload(
        {"triage": True, "override": True}, status="IN_PROGRESS", note="", owner="", business_impact=None,
        effort=None, due=datetime.date.fromisoformat(dec["sla_due_date"]), priority="IKUTI")
    assert client.put(f"/api/v1/decisions/{item['decision_key']}", json=payload, headers=h).status_code == 200
    item2 = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False}).json()["items"][0]
    assert item2["business_impact_is_default"] and item2["decision"]["asset_criticality"] is None


def test_business_impact_from_config_rule_is_not_reported_as_default(client, monkeypatch):
    """Nilai dari aturan pola komponen di konfigurasi bukan 'belum dinilai'."""
    from backend.dss import service
    from backend.dss.config import load_dss_config
    cfg = load_dss_config()
    cfg["asset_criticality"] = {"default": 3, "rules": [{"pattern": "payment", "value": 5}]}
    monkeypatch.setattr(service, "load_dss_config", lambda: cfg)
    batch = _seed_pairs(client, [_pair(1, "CWE-79", "XSS (config rule test)", 7.5, file="src/payment.php")])
    item = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False}).json()["items"][0]
    assert item["business_impact"] == 5 and not item["business_impact_is_default"]
    assert "belum dinilai" not in item["why"]


def _seed_source_batches(client, tag):
    """Satu batch SAST dan satu batch DAST ber-CWE sama (sudah diberi skor) untuk korelasi."""
    sast_id, dast_id = f"SAST-{tag}", f"DAST-{tag}"
    with session_scope(client.app.state.database_url) as s:
        history_repo.save_findings(s, sast_id, history_repo.SAST_SCANNER, [{
            "key_id": f"S-{tag}", "cwe_id": "CWE-79", "component": f"src/{tag}.php",
            "issue_description": "XSS di kode", "predicted_cvss4_score": 7.2, "predicted_severity": "HIGH"}])
        history_repo.save_findings(s, dast_id, history_repo.DAST_SCANNER, [{
            "key_id": f"XSS auto-record {tag}", "cwe_id": "CWE-79", "component": f"GET https://app.test/{tag}",
            "issue_description": "XSS di aplikasi", "predicted_cvss4_score": 7.6, "predicted_severity": "HIGH"}])
    return sast_id, dast_id


@pytest.fixture
def fake_hybrid_scoring(monkeypatch):
    """Mengganti skoring ML hybrid dengan hasil sintetis agar tes tidak memerlukan artefak model."""
    from backend.services import scoring

    def fake(pairs):
        return [{"key_id": p["pair_id"], "cwe_id": p["cwe_id"],
                 "component": f"{p['sast_component']} | {p['dast_component']}", "issue_description": "x",
                 "predicted_cvss4_score": 7.8, "predicted_severity": "HIGH", "base_score": 7.4,
                 "sast_score": 7.2, "dast_score": 7.6, "is_true_positive": True,
                 "sast_component": p["sast_component"], "dast_component": p["dast_component"],
                 "sast_key_id": p["sast_key_id"], "dast_key_id": p["dast_key_id"],
                 "decision_key": p["decision_key"]} for p in pairs]
    monkeypatch.setattr(scoring, "score_pairs", fake)
    monkeypatch.setattr(scoring, "missing_shap_updates", lambda rows: [])


@pytest.fixture
def fake_shap(monkeypatch):
    """Mengganti TreeExplainer dengan hasil sintetis; mencatat teks yang dihitung."""
    from backend import engine
    seen = []

    def fake(pairs):
        seen.extend(pairs)
        return [{"shap_base_value": 6.26, "shap_total_pos": 0.4, "shap_total_neg": -0.1, "absent_vocab_bias": 0.0,
                 "shap_predicted_score": 6.56, "shap_positive": "password (+0.40)",
                 "shap_negative": "file (-0.10)"} for _ in pairs]
    monkeypatch.setattr(engine, "calculate_dynamic_shap_batch", fake)
    return seen


def test_correlation_run_records_issues_when_logged_in(client, analyst_token, fake_hybrid_scoring):
    sast_id, dast_id = _seed_source_batches(client, uuid.uuid4().hex[:6])
    r = client.post("/api/v1/correlation/run", json={"sast_batch_id": sast_id, "dast_batch_id": dast_id},
                    headers=_auth(analyst_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dss"]["recorded"] is True and body["dss"]["issues"] == 1
    decisions = client.get("/api/v1/decisions", params={"batch_id": body["batch_id"]}).json()["decisions"]
    assert len(decisions) == 1 and decisions[0]["recommended_action"]
    events = client.get(f"/api/v1/decisions/{decisions[0]['decision_key']}/events").json()["events"]
    assert events and events[0]["actor"] == "analis_uji"


def test_correlation_run_without_login_is_rejected(client, fake_hybrid_scoring):
    tag = uuid.uuid4().hex[:6]
    sast_id, dast_id = _seed_source_batches(client, tag)
    r = client.post("/api/v1/correlation/run", json={"sast_batch_id": sast_id, "dast_batch_id": dast_id})
    assert r.status_code == 401
    # Dicari menurut judul unik: ID sesi HAST-<detik> dapat sama untuk dua korelasi dalam detik yang sama.
    titles = [d["title"] for d in client.get("/api/v1/decisions").json()["decisions"]]
    assert f"XSS auto-record {tag}" not in titles


@pytest.mark.parametrize("role", ["developer", "auditor"])
def test_correlation_run_role_without_processing_right_is_rejected(client, token_for, fake_hybrid_scoring, role):
    sast_id, dast_id = _seed_source_batches(client, uuid.uuid4().hex[:6])
    r = client.post("/api/v1/correlation/run", json={"sast_batch_id": sast_id, "dast_batch_id": dast_id},
                    headers=_auth(token_for(role)))
    assert r.status_code == 403


PROCESSING_REQUESTS = {
    "ingest_sonarqube": ("/api/v1/ingest/sonarqube", {"files": {"file": ("s.json", b'{"issues": []}')}}),
    "ingest_zap": ("/api/v1/ingest/zap", {"files": {"file": ("z.json", b'{"site": []}')}}),
    "batches": ("/api/v1/batches", {"json": {"scanner": "SAST", "records": [
        {"key_id": "RBAC", "issue_type": "CODE_SMELL", "has_cwe_tag": False, "issue_description": "x"}]}}),
    "history_shap": ("/api/v1/history/shap", {"json": {"items": []}}),
}


@pytest.mark.parametrize("name", PROCESSING_REQUESTS)
def test_processing_endpoints_require_right(client, token_for, name):
    """Endpoint yang menerima laporan atau menulis temuan menolak tamu (401) dan role tanpa hak (403)."""
    path, kwargs = PROCESSING_REQUESTS[name]
    assert client.post(path, **kwargs).status_code == 401
    for role in ("developer", "auditor"):
        assert client.post(path, headers=_auth(token_for(role)), **kwargs).status_code == 403
    for role in ("analyst", "manager", "admin"):
        assert client.post(path, headers=_auth(token_for(role)), **kwargs).status_code == 200


def test_guest_cannot_overwrite_stored_description(client):
    batch, _ = _seed_source_batches(client, uuid.uuid4().hex[:6])
    row = client.get(f"/api/v1/batches/{batch}").json()["rows"][0]
    r = client.post("/api/v1/history/shap", json={"items": [{"id": row["id"], "sast_description": "diubah tamu"}]})
    assert r.status_code == 401
    assert client.get(f"/api/v1/batches/{batch}").json()["rows"][0]["sast_description"] == row["sast_description"]


def test_history_shap_of_guest_is_computed_without_storing(monkeypatch):
    """Tamu tetap melihat SHAP riwayat lewat endpoint tanpa status; pengguna berhak memakai endpoint penyimpan."""
    import streamlit as st

    from frontend.utils import api_client
    calls = []

    def fake_request(method, path, **kwargs):
        calls.append((path, kwargs["json"]))
        return {"results": []}
    monkeypatch.setattr(api_client, "_request", fake_request)
    item = {"id": 7, "sast_description": "a", "dast_description": None}
    monkeypatch.setattr(st, "session_state", {})
    api_client.compute_history_shap([item])
    monkeypatch.setattr(st, "session_state", {"auth_user": {"permissions": ["dss.save_run"]}})
    api_client.compute_history_shap([item])
    assert calls[0] == ("/api/v1/scoring/shap/batch", {"pairs": [{"sast_description": "a", "dast_description": ""}]})
    assert calls[1] == ("/api/v1/history/shap", {"items": [item]})


def test_correlation_run_prioritises_single_scanner_findings(client, analyst_token, fake_hybrid_scoring):
    tag = uuid.uuid4().hex[:6]
    sast_id, dast_id = _seed_source_batches(client, tag)
    with session_scope(client.app.state.database_url) as s:
        history_repo.save_findings(s, sast_id, history_repo.SAST_SCANNER, [{
            "key_id": f"S2-{tag}", "cwe_id": "CWE-798", "component": f"src/{tag}-secret.php",
            "issue_description": f"Hardcoded password {tag}", "predicted_cvss4_score": 6.8,
            "predicted_severity": "MEDIUM"}])
        history_repo.save_findings(s, dast_id, history_repo.DAST_SCANNER, [{
            "key_id": f"SQL Injection {tag}", "cwe_id": "CWE-89", "component": f"GET https://app.test/{tag}?q=1",
            "issue_description": "SQL injection may be possible.", "predicted_cvss4_score": 8.21,
            "predicted_severity": "HIGH"}])
    r = client.post("/api/v1/correlation/run", json={"sast_batch_id": sast_id, "dast_batch_id": dast_id},
                    headers=_auth(analyst_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["unpaired_count"] == 2 and len(body["records"]) == 1
    assert body["dss"]["recorded"] is True
    items = client.post("/api/v1/dss/rank", json={"batch_id": body["batch_id"], "persist": False}).json()["items"]
    mine = {i["source"]: i for i in items if tag in i["title"] or tag in " ".join(i["files"] + i["endpoints"])}
    assert set(mine) == {"hybrid", "sast", "dast"}
    assert mine["dast"]["is_true_positive"] is False and mine["dast"]["hybrid_score"] == 8.21
    assert mine["dast"]["priority"] == "P2" and mine["dast"]["recommendation"]["rule_id"] == "R3"
    assert mine["sast"]["priority"] == "P3" and "hanya terdeteksi di kode" in mine["sast"]["why"]
    tp = {c["key"]: c["value"] for c in mine["dast"]["criteria"]}["true_positive"]
    assert tp == 0.0


def _fake_single_prediction(monkeypatch):
    from backend import engine
    monkeypatch.setattr(engine, "run_single_prediction",
                        lambda *a, **k: {"predicted_cvss4_score": 6.56, "predicted_severity": "MEDIUM"})


def test_create_batch_stores_shap_for_every_model_score(client, analyst_token, monkeypatch, fake_shap):
    _fake_single_prediction(monkeypatch)
    records = [
        {"key_id": "K1", "cwe_id": "CWE-798", "component": "a.php", "issue_description": "Hardcoded password",
         "issue_type": "VULNERABILITY", "has_cwe_tag": True},
        # Ditolak aturan penyaringan (skor 0), sehingga tidak memiliki prediksi untuk dijelaskan
        {"key_id": "K2", "cwe_id": "N/A", "component": "b.php", "issue_description": "Unused variable",
         "issue_type": "CODE_SMELL", "has_cwe_tag": False}]
    body = client.post("/api/v1/batches", json={"scanner": "SAST", "records": records},
                       headers=_auth(analyst_token)).json()
    rows = {r["key_id"]: r for r in client.get(f"/api/v1/batches/{body['batch_id']}").json()["rows"]
            if r["key_id"] in ("K1", "K2")}
    assert rows["K1"]["shap_base_value"] == 6.26 and rows["K1"]["shap_positive"] == "password (+0.40)"
    assert rows["K1"]["predicted_score"] == 6.56 and rows["K1"]["description"] == "Hardcoded password"
    assert rows["K2"]["predicted_score"] == 0.0 and not rows["K2"]["shap_base_value"]
    assert ("Hardcoded password", "") in fake_shap and ("Unused variable", "") not in fake_shap


def test_create_batch_keeps_scores_when_shap_fails(client, analyst_token, monkeypatch):
    from backend import engine
    _fake_single_prediction(monkeypatch)

    def broken(pairs):
        raise RuntimeError("TreeExplainer gagal")
    monkeypatch.setattr(engine, "calculate_dynamic_shap_batch", broken)
    r = client.post("/api/v1/batches", headers=_auth(analyst_token), json={"scanner": "DAST", "records": [
        {"key_id": "ALERT-SHAP-GAGAL", "cwe_id": "CWE-89", "component": "GET https://app.test/x",
         "issue_description": "SQL injection"}]})
    assert r.status_code == 200, r.text
    rows = client.get(f"/api/v1/batches/{r.json()['batch_id']}").json()["rows"]
    assert [x["predicted_score"] for x in rows if x["key_id"] == "ALERT-SHAP-GAGAL"] == [6.56]


def test_correlation_fills_shap_of_single_findings_from_old_sessions(client, analyst_token, fake_shap):
    """Temuan tunggal dari sesi lama tanpa SHAP tetap memperoleh penjelasan model pada isu DSS."""
    tag = uuid.uuid4().hex[:6]
    sast_id, dast_id = f"SAST-{tag}", f"DAST-{tag}"
    with session_scope(client.app.state.database_url) as s:
        history_repo.save_findings(s, sast_id, history_repo.SAST_SCANNER, [{
            "key_id": f"S-{tag}", "cwe_id": "CWE-798", "component": f"src/{tag}.php",
            "issue_description": f"Hardcoded password {tag}", "predicted_cvss4_score": 6.56,
            "predicted_severity": "MEDIUM"}])
        history_repo.save_findings(s, dast_id, history_repo.DAST_SCANNER, [{
            "key_id": f"SQL Injection {tag}", "cwe_id": "CWE-89", "component": f"GET https://app.test/{tag}",
            "issue_description": f"SQL injection {tag}", "comment_solution": "Pakai prepared statement.",
            "predicted_cvss4_score": 8.2, "predicted_severity": "HIGH"}])
    body = client.post("/api/v1/correlation/run", json={"sast_batch_id": sast_id, "dast_batch_id": dast_id},
                       headers=_auth(analyst_token)).json()
    # ID sesi berbasis detik dapat sama antartes, jadi hanya teks milik tes ini yang dibandingkan.
    assert sorted(p for p in fake_shap if tag in "".join(p)) == [
        ("", f"SQL injection {tag}"), (f"Hardcoded password {tag}", "")]
    items = client.post("/api/v1/dss/rank", json={"batch_id": body["batch_id"], "persist": False}).json()["items"]
    mine = [i for i in items if tag in " ".join(i["files"] + i["endpoints"])]
    assert len(mine) == 2
    assert all(i["score_explanation"]["shap"]["base_value"] == 6.26 for i in mine)


def test_correlation_without_cwe_overlap_is_still_prioritised(client, analyst_token, fake_shap):
    """Sesi tanpa irisan CWE tetap tersimpan, tercatat di DSS, dan muncul pada daftar sesi DSS."""
    tag = uuid.uuid4().hex[:6]
    sast_id, dast_id = f"SAST-{tag}", f"DAST-{tag}"
    with session_scope(client.app.state.database_url) as s:
        history_repo.save_findings(s, sast_id, history_repo.SAST_SCANNER, [{
            "key_id": f"S-{tag}", "cwe_id": "CWE-798", "component": f"src/{tag}.php",
            "issue_description": "Hardcoded password", "predicted_cvss4_score": 6.8, "predicted_severity": "MEDIUM"}])
        history_repo.save_findings(s, dast_id, history_repo.DAST_SCANNER, [{
            "key_id": f"SQL Injection {tag}", "cwe_id": "CWE-89", "component": f"GET https://app.test/{tag}",
            "issue_description": "SQL injection", "predicted_cvss4_score": 8.2, "predicted_severity": "HIGH"}])
    ids = {"sast_batch_id": sast_id, "dast_batch_id": dast_id}
    assert client.post("/api/v1/correlation/preview", json=ids).json()["pairs"] == []
    body = client.post("/api/v1/correlation/run", json=ids, headers=_auth(analyst_token)).json()
    assert body["records"] == [] and body["unpaired_count"] == 2 and body["dss"]["recorded"] is True
    listed = [b["batch_id"] for b in client.get("/api/v1/batches", params={"dss": True}).json()["batches"]]
    assert listed.count(body["batch_id"]) == 1
    assert not any(b.startswith(("SAST-", "DAST-")) for b in listed)


def test_clear_hybrid_history_also_removes_single_scanner_rows(db_url):
    row = {"key_id": "K", "cwe_id": "CWE-79", "component": "a | b", "issue_description": "x",
           "predicted_cvss4_score": 5.0, "predicted_severity": "MEDIUM"}
    with session_scope(db_url) as s:
        history_repo.save_findings(s, "HAST-1", history_repo.HYBRID_SCANNER, [row])
        history_repo.save_findings(s, "HAST-1", history_repo.SINGLE_SCANNER, [row])
        history_repo.save_findings(s, "HAST-2", history_repo.SINGLE_SCANNER, [row])
        history_repo.save_findings(s, "SAST-1", history_repo.SAST_SCANNER, [row])
        listed = [(b["batch_id"], b["count"]) for b in history_repo.list_dss_batches(s)]
        assert listed == [("HAST-2", 1), ("HAST-1", 2)]
        assert history_repo.clear_scanner(s, history_repo.HYBRID_SCANNER) == 3
        assert history_repo.list_dss_batches(s) == [] and history_repo.list_batch(s, "SAST-1")


def test_rank_records_normalization_and_vector_is_what_if(client, analyst_token):
    batch = _seed_hybrid_batch(client)
    body = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False}).json()
    assert body["normalization"] == "minmax" and body["normalization_overridden"] is False
    vec = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False, "normalization": "vector"}).json()
    assert vec["normalization"] == "vector" and vec["normalization_overridden"] is True
    r = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": True, "normalization": "vector"},
                    headers=_auth(analyst_token))
    assert r.status_code == 422
    bad = client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": False, "normalization": "zscore"})
    assert bad.status_code == 422
