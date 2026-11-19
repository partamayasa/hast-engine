# tests/test_rbac.py
"""Kendali akses berbasis peran: katalog peran, hak per peran, aturan keputusan per kolom, dan pengaman admin."""
import uuid

import pytest

from backend.core.roles import ROLES, has_permission
from backend.db.session import session_scope
from backend.repositories import history as history_repo


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _issue(client, manager_token):
    """Menyiapkan satu pasangan hybrid dan mencatat rekomendasinya; mengembalikan decision_key isu tersebut."""
    batch = f"HAST-R{uuid.uuid4().hex[:6]}"
    alert = f"Alert RBAC {uuid.uuid4().hex[:6]}"
    with session_scope(client.app.state.database_url) as s:
        history_repo.save_findings(s, batch, history_repo.HYBRID_SCANNER, [{
            "key_id": "PAIR-RBAC0001", "cwe_id": "CWE-79", "component": "src/a.php | GET https://x/",
            "issue_description": "x", "predicted_cvss4_score": 7.4, "predicted_severity": "HIGH",
            "base_score": 7.4, "is_true_positive": True, "sast_component": "src/a.php",
            "dast_component": "GET https://x/", "dast_key_id": alert}])
    run = client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=_auth(manager_token)).json()
    return batch, run["items"][0]["decision_key"]


def test_role_catalogue_lists_five_roles(client):
    roles = client.get("/api/v1/roles").json()["roles"]
    assert [r["key"] for r in roles] == ["admin", "manager", "analyst", "developer", "auditor"]
    assert all(r["label"] and r["description"] for r in roles)


def test_login_returns_role_label_and_permissions(client, token_for):
    tok = token_for("developer")
    me = client.get("/api/v1/auth/me", headers=_auth(tok)).json()
    assert me["role_label"] == "Pengembang" and me["permissions"] == ["decision.update_progress"]


@pytest.mark.parametrize("role,perm,allowed", [
    ("admin", "users.manage", True), ("manager", "users.manage", False),
    ("manager", "decision.accept_risk", True), ("analyst", "decision.accept_risk", False),
    ("analyst", "history.delete", False), ("developer", "decision.triage", False),
    ("auditor", "report.export", True), ("auditor", "decision.update_progress", False),
])
def test_permission_matrix(role, perm, allowed):
    assert has_permission(role, perm) is allowed


def test_developer_can_only_update_progress(client, manager_token, token_for):
    batch, key = _issue(client, manager_token)
    dev = _auth(token_for("developer"))
    assert client.put(f"/api/v1/decisions/{key}", headers=dev,
                      json={"status": "IN_PROGRESS", "reason": "Sedang diperbaiki di cabang fix/xss"}).status_code == 200
    assert client.put(f"/api/v1/decisions/{key}", headers=dev, json={"owner": "saya"}).status_code == 403
    assert client.put(f"/api/v1/decisions/{key}", headers=dev,
                      json={"status": "FALSE_POSITIVE", "reason": "x"}).status_code == 403
    assert client.put(f"/api/v1/decisions/{key}", headers=dev, json={"chosen_action": "PLAN"}).status_code == 403
    # Membuka daftar kerja tidak boleh menyimpan run untuk peran yang hanya melihat dan memperbarui progres.
    assert client.post("/api/v1/dss/rank", json={"batch_id": batch}, headers=dev).status_code == 403
    assert client.get("/api/v1/decisions/export.xlsx", headers=dev).status_code == 403


def test_unchanged_fields_do_not_trigger_permission_checks(client, manager_token, token_for):
    """Form UI mengirim ulang semua kolom; hanya kolom yang berubah yang diperiksa haknya."""
    _batch, key = _issue(client, manager_token)
    client.put(f"/api/v1/decisions/{key}", headers=_auth(manager_token), json={"owner": "Tim Web"})
    dev = _auth(token_for("developer"))
    r = client.put(f"/api/v1/decisions/{key}", headers=dev,
                   json={"owner": "Tim Web", "status": "RESOLVED", "reason": "Sudah dirilis"})
    assert r.status_code == 200 and r.json()["status"] == "RESOLVED"


def test_only_manager_or_admin_can_accept_risk(client, manager_token, analyst_token):
    _batch, key = _issue(client, manager_token)
    body = {"status": "ACCEPTED_RISK", "reason": "Kontrol kompensasi WAF aktif"}
    assert client.put(f"/api/v1/decisions/{key}", headers=_auth(analyst_token), json=body).status_code == 403
    assert client.put(f"/api/v1/decisions/{key}", headers=_auth(manager_token), json=body).status_code == 200


def test_auditor_is_read_only(client, manager_token, token_for):
    _batch, key = _issue(client, manager_token)
    aud = _auth(token_for("auditor"))
    assert client.put(f"/api/v1/decisions/{key}", headers=aud, json={"status": "IN_PROGRESS"}).status_code == 403
    assert client.get("/api/v1/decisions/export.xlsx", headers=aud).status_code == 200
    assert client.get("/api/v1/sus", headers=aud).status_code == 200


def test_admin_manages_users_and_roles(client, manager_token, token_for):
    admin = _auth(token_for("admin"))
    assert client.get("/api/v1/users", headers=_auth(manager_token)).status_code == 403
    name = f"budi_{uuid.uuid4().hex[:5]}"
    r = client.post("/api/v1/users", headers=admin,
                    json={"username": name, "password": "rahasia-123456", "role": "developer"})
    assert r.status_code == 201 and r.json()["role_label"] == "Pengembang"
    r = client.patch(f"/api/v1/users/{name}", headers=admin, json={"role": "analyst", "is_active": False})
    assert r.status_code == 200 and r.json()["role"] == "analyst" and r.json()["is_active"] is False
    assert client.patch(f"/api/v1/users/{name}", headers=admin, json={"role": "superuser"}).status_code == 422


def test_admin_guards(client, token_for):
    admin_tok = token_for("admin")
    admin = _auth(admin_tok)
    # Menonaktifkan diri sendiri ditolak.
    assert client.patch("/api/v1/users/uji_admin", headers=admin, json={"is_active": False}).status_code == 422
    # Menurunkan Administrator aktif terakhir ditolak.
    users = client.get("/api/v1/users", headers=admin).json()["users"]
    active_admins = [u for u in users if u["role"] == "admin" and u["is_active"]]
    if len(active_admins) == 1:
        assert client.patch("/api/v1/users/uji_admin", headers=admin, json={"role": "manager"}).status_code == 422


def test_roles_module_consistency():
    for key, r in ROLES.items():
        assert r["label"] and r["description"]
        assert r["permissions"] <= ROLES["admin"]["permissions"], key
