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


def test_sus_submit_public_list_private(client, analyst_token):
    r = client.post("/api/v1/sus", json={"respondent_name": "R-Uji", "profession": "QA",
                                          "answers": {f"q{i}": (5 if i % 2 else 1) for i in range(1, 11)}})
    assert r.status_code == 200 and r.json()["sus_score"] == 100.0
    assert client.get("/api/v1/sus").status_code == 401
    rows = client.get("/api/v1/sus", headers=_auth(analyst_token)).json()["rows"]
    assert rows[-1]["Versi UI"] == "v2-dss"


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


def test_correlation_run_without_login_does_not_record(client, fake_hybrid_scoring):
    tag = uuid.uuid4().hex[:6]
    sast_id, dast_id = _seed_source_batches(client, tag)
    body = client.post("/api/v1/correlation/run", json={"sast_batch_id": sast_id, "dast_batch_id": dast_id}).json()
    assert body["batch_id"] and body["dss"] == {"recorded": False, "reason": "not_logged_in"}
    # Dicari menurut judul unik: ID sesi HAST-<detik> dapat sama untuk dua korelasi dalam detik yang sama.
    titles = [d["title"] for d in client.get("/api/v1/decisions").json()["decisions"]]
    assert f"XSS auto-record {tag}" not in titles


def test_correlation_run_role_without_save_right_does_not_record(client, token_for, fake_hybrid_scoring):
    sast_id, dast_id = _seed_source_batches(client, uuid.uuid4().hex[:6])
    body = client.post("/api/v1/correlation/run", json={"sast_batch_id": sast_id, "dast_batch_id": dast_id},
                       headers=_auth(token_for("developer"))).json()
    assert body["batch_id"] and body["dss"] == {"recorded": False, "reason": "not_permitted"}
