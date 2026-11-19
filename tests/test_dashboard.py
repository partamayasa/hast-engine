# tests/test_dashboard.py
"""Ringkasan dasbor: logika agregasi murni dan endpoint /api/v1/dashboard."""
import datetime

from backend.dss.dashboard import UNASSIGNED, build_summary
from tests.test_dss_api import _auth, _seed_hybrid_batch

TODAY = datetime.date(2026, 11, 18)


def _decision(key, priority="P1", status="OPEN", owner=None, due=None, cwe="CWE-79", decided_by=None,
              recommended="REMEDIATE_NOW", chosen=None, needs_review=False):
    closed = status in ("RESOLVED", "ACCEPTED_RISK", "FALSE_POSITIVE")
    return {
        "decision_key": key, "title": f"Isu {key}", "cwe_id": cwe, "priority": priority,
        "priority_label": {"P1": "P1 · Segera", "P2": "P2 · Terjadwal"}.get(priority, priority),
        "status": status, "status_label": status, "owner": owner, "sla_due_date": due, "is_closed": closed,
        "is_overdue": bool(due and not closed and due < TODAY.isoformat()), "decided_by": decided_by,
        "recommended_action": recommended, "chosen_action": chosen, "needs_review": needs_review,
    }


def test_summary_kpis_and_deadlines():
    decisions = [
        _decision("a", due="2026-11-10", owner="budi"),                       # lewat tenggat
        _decision("b", priority="P2", due="2026-11-20", status="IN_PROGRESS",  # tenggat dekat
                  owner="budi", cwe="CWE-89", decided_by="analis"),
        _decision("c", priority="P2", status="RESOLVED", decided_by="analis",
                  recommended="REMEDIATE_SCHEDULED", chosen="REMEDIATE_NOW"),
        _decision("d", priority="P1", due="2027-01-01", needs_review=True),
    ]
    s = build_summary(decisions, [], today=TODAY)
    k = s["kpis"]
    assert (k["total_issues"], k["open_issues"], k["p1_open"], k["overdue"], k["due_soon"]) == (4, 3, 2, 1, 1)
    assert k["closed_issues"] == 1 and k["closure_rate"] == 0.25
    assert k["unassigned_open"] == 1 and k["needs_review_open"] == 1 and k["in_progress"] == 1
    # Isu b mengikuti rekomendasi (chosen kosong), isu c mengubah prioritas.
    assert k["agreement"] == {"decided": 2, "agreed": 1, "rate": 0.5}
    assert [r["decision_key"] for r in s["deadlines"]] == ["a", "b", "d"]
    assert s["deadlines"][0]["days_left"] == -8


def test_summary_rankings_are_deterministic():
    decisions = [_decision("a", cwe="CWE-89"), _decision("b", cwe="CWE-79"), _decision("c", cwe="CWE-79", owner="sari"),
                 _decision("d", cwe="CWE-22", status="RESOLVED")]
    s = build_summary(decisions, [], today=TODAY)
    assert [c["cwe_id"] for c in s["top_cwe"]] == ["CWE-79", "CWE-89"]  # CWE tertutup tidak dihitung
    assert s["owner_load"][0] == {"owner": UNASSIGNED, "open": 2, "p1_open": 2, "overdue": 0}
    p1_open = [r for r in s["priority_status"] if r["priority"] == "P1" and r["status"] == "OPEN"]
    assert p1_open[0]["count"] == 3


def test_summary_latest_scan_per_scanner():
    stats = [{"batch_id": "B3", "scanner_type": "S", "severity": {}}, {"batch_id": "B2", "scanner_type": "D", "severity": {}},
             {"batch_id": "B1", "scanner_type": "S", "severity": {}}]
    s = build_summary([], stats, today=TODAY)
    assert [b["batch_id"] for b in s["latest_scans"]] == ["B3", "B2"]
    assert [b["batch_id"] for b in s["scan_trend"]] == ["B1", "B2", "B3"]
    assert s["kpis"]["closure_rate"] is None


def test_dashboard_endpoint(client, analyst_token):
    batch = _seed_hybrid_batch(client)
    client.post("/api/v1/dss/rank", json={"batch_id": batch, "persist": True}, headers=_auth(analyst_token))
    r = client.get("/api/v1/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert data["kpis"]["total_issues"] >= 4
    scan = next(b for b in data["latest_scans"] if b["batch_id"] == batch)
    assert scan["count"] == 4 and scan["true_positive"] == 3
    assert scan["severity"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 2}
    assert scan["max_score"] == 9.2
    assert client.get("/api/v1/dashboard?due_soon_days=0").status_code == 422
