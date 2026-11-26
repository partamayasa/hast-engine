# frontend/components/blackbox_dss.py
"""
Kasus uji Black-Box untuk lapisan DSS (Subbab 3.6.4, modul A dan D sampai H).

Setiap kasus dijalankan sebagai permintaan HTTP ke aplikasi FastAPI di dalam proses (TestClient), sehingga yang
diamati hanya masukan berupa permintaan dan keluaran berupa respons, tanpa memeriksa kode internal. Seluruh kasus
berjalan pada basis data sementara dan berkas konfigurasi DSS sementara, sehingga basis data riset dan kebijakan
yang berlaku tidak pernah diubah, termasuk ketika dijalankan dari halaman Pengujian Black-Box di server.

Dipakai oleh frontend/components/tab_blackbox_testing.py dan tests/test_blackbox_dss.py.
"""
import datetime
import os
import shutil
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable

MODULE_LABELS = {
    "A": "Modul A - Autentikasi & Hak Akses",
    "B": "Modul B - Unggah, Parsing & Riwayat",
    "C": "Modul C - Estimasi Skor & SHAP",
    "D": "Modul D - Korelasi Hybrid & Isu",
    "E": "Modul E - Kelas Prioritas & Pengurutan",
    "F": "Modul F - Rekomendasi & SLA",
    "G": "Modul G - Tindak Lanjut & Jejak Audit",
    "H": "Modul H - Kebijakan, Sensitivitas & Ekspor",
}
PASSWORD = "rahasia-uji-123"
ROLE_USERS = {"admin": "bb_admin", "manager": "bb_manajer", "analyst": "bb_analis",
              "developer": "bb_pengembang", "auditor": "bb_auditor"}
SESSION_ID = "HAST-BLACKBOX"


@dataclass
class Case:
    case_id: str
    module: str
    title: str
    steps: str
    given: str
    expected: str
    criteria: str
    run: Callable[["Context"], str]


class Context:
    """Klien HTTP, token per peran, dan sesi uji yang dipakai bersama oleh seluruh kasus."""

    def __init__(self, client, db_url: str):
        self.client = client
        self.db_url = db_url
        self.tokens: dict[str, str] = {}

    def auth(self, role: str) -> dict:
        return {"Authorization": f"Bearer {self.tokens[role]}"}

    def rank(self, persist: bool = False, role: str | None = None, **extra) -> dict:
        r = self.client.post("/api/v1/dss/rank", json={"batch_id": SESSION_ID, "persist": persist, **extra},
                             headers=self.auth(role) if role else None)
        assert r.status_code == 200, f"Ranking gagal: HTTP {r.status_code} {r.text[:200]}"
        return r.json()

    def item(self, title: str, run: dict | None = None) -> dict:
        items = (run or self.rank())["items"]
        found = [it for it in items if it["title"] == title]
        assert found, f"Isu '{title}' tidak ditemukan."
        return found[0]


def _pair(key, cwe, alert, sast_file, endpoint, score, severity, base):
    return {"key_id": key, "cwe_id": cwe, "component": f"{sast_file} | {endpoint}",
            "issue_description": f"[SAST]: temuan {key}\n[DAST]: {alert}", "predicted_cvss4_score": score,
            "predicted_severity": severity, "base_score": base, "sast_score": base, "dast_score": base,
            "is_true_positive": True, "sast_component": sast_file, "dast_component": endpoint,
            "sast_key_id": f"S-{key}", "dast_key_id": alert}


def _single_dast(key, cwe, alert, endpoint, score, severity):
    return {"key_id": key, "cwe_id": cwe, "component": f" | {endpoint}", "issue_description": f"[DAST]: {alert}",
            "predicted_cvss4_score": score, "predicted_severity": severity, "base_score": score,
            "sast_score": 0.0, "dast_score": score, "is_true_positive": False, "sast_component": "",
            "dast_component": endpoint, "sast_key_id": None, "dast_key_id": alert}


def _seed(ctx: Context) -> None:
    """Membuat akun per peran dan satu sesi hybrid berisi isu dengan kelas keparahan yang berbeda."""
    from backend.db.session import session_scope
    from backend.repositories import history as history_repo
    from backend.repositories import users as users_repo

    with session_scope(ctx.db_url) as s:
        for role, name in ROLE_USERS.items():
            users_repo.create_user(s, name, PASSWORD, role=role)
        history_repo.save_findings(s, SESSION_ID, history_repo.HYBRID_SCANNER, [
            _pair("P1", "CWE-79", "Cross Site Scripting (Reflected)", "src/Search.php", "GET https://app.uji/?q=x",
                  9.37, "CRITICAL", 9.30),
            _pair("P2", "CWE-614", "Cookie Without Secure Flag", "src/Auth.php", "GET https://app.uji/", 7.30,
                  "HIGH", 7.00),
            _pair("P3", "CWE-614", "Cookie Without Secure Flag", "src/Session.php", "GET https://app.uji/", 7.21,
                  "HIGH", 6.90),
            _pair("P4", "CWE-693", "Content Security Policy (CSP) Header Not Set", "src/Layout.php",
                  "GET https://app.uji/", 6.40, "MEDIUM", 6.00),
        ])
        history_repo.save_findings(s, SESSION_ID, history_repo.SINGLE_SCANNER, [
            _single_dast("S1", "CWE-89", "SQL Injection", "GET https://app.uji/?id=1", 8.21, "HIGH"),
            _single_dast("S2", "CWE-319", "Strict-Transport-Security Header Not Set", "GET https://app.uji/", 6.72,
                         "MEDIUM"),
        ])
    for role, name in ROLE_USERS.items():
        r = ctx.client.post("/api/v1/auth/login", data={"username": name, "password": PASSWORD})
        ctx.tokens[role] = r.json()["access_token"]
    # Sama dengan alur korelasi saat analis login: isu dan rekomendasinya langsung dicatat sebagai keputusan.
    ctx.rank(persist=True, role="analyst")


@contextmanager
def dss_harness():
    """Basis data sementara, berkas konfigurasi DSS sementara, dan TestClient pada aplikasi FastAPI."""
    from fastapi.testclient import TestClient

    from backend.core.settings import get_settings
    from backend.db.bootstrap import init_database
    from backend.db.session import dispose_engine, sqlite_url_for
    from backend.main import create_app

    settings = get_settings()
    tmp_dir = tempfile.mkdtemp(prefix="hast_blackbox_")
    db_path = os.path.join(tmp_dir, "blackbox.db")
    db_url = sqlite_url_for(db_path)
    original_config_path = settings.dss_config_path
    # Konfigurasi DSS yang diubah kasus H ditulis ke folder sementara, bukan ke backend/config/dss_config.json.
    # Salinannya diambil dari konfigurasi aktif agar kasus uji memakai kebijakan yang sama dengan sistem.
    tmp_config_path = type(original_config_path)(os.path.join(tmp_dir, "dss_config.json"))
    if not original_config_path.exists():
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise FileNotFoundError(f"Konfigurasi DSS tidak ditemukan: {original_config_path}. "
                                f"Buat dari templat: cp {settings.dss_config_sample_path} {original_config_path}")
    shutil.copyfile(original_config_path, tmp_config_path)
    settings.dss_config_path = tmp_config_path
    try:
        init_database(db_url, force=True)
        app = create_app(database_url=db_url, load_models=False)
        with TestClient(app) as client:
            ctx = Context(client, db_url)
            _seed(ctx)
            yield ctx
    finally:
        settings.dss_config_path = original_config_path
        dispose_engine(db_url)
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Modul A: autentikasi dan hak akses
# ---------------------------------------------------------------------------
def tc_auth_01(ctx):
    me = ctx.client.get("/api/v1/auth/me", headers=ctx.auth("analyst")).json()
    assert me["role"] == "analyst", me
    return f"Login berhasil; token diterima dan /auth/me mengembalikan peran '{me['role']}'."


def tc_auth_02(ctx):
    r = ctx.client.post("/api/v1/auth/login", data={"username": ROLE_USERS["analyst"], "password": "salah-sekali"})
    assert r.status_code == 401, r.status_code
    return "Login ditolak dengan HTTP 401 tanpa token."


def tc_auth_03(ctx):
    r = ctx.client.post("/api/v1/dss/rank", json={"batch_id": SESSION_ID, "persist": True})
    assert r.status_code == 401, r.status_code
    return "Menyimpan hasil prioritas tanpa login ditolak dengan HTTP 401."


def tc_auth_04(ctx):
    r = ctx.client.post("/api/v1/dss/rank", json={"batch_id": SESSION_ID, "persist": True},
                        headers=ctx.auth("developer"))
    assert r.status_code == 403, r.status_code
    return "Pengembang yang menyimpan hasil prioritas ditolak dengan HTTP 403."


def tc_auth_05(ctx):
    key = ctx.item("SQL Injection")["decision_key"]
    r = ctx.client.put(f"/api/v1/decisions/{key}", headers=ctx.auth("analyst"),
                       json={"status": "ACCEPTED_RISK", "reason": "Uji hak akses"})
    assert r.status_code == 403, r.status_code
    return "Analis yang menetapkan status 'Risiko diterima' ditolak dengan HTTP 403."


def tc_auth_06(ctx):
    key = ctx.item("SQL Injection")["decision_key"]
    r = ctx.client.put(f"/api/v1/decisions/{key}", headers=ctx.auth("auditor"), json={"status": "IN_PROGRESS"})
    assert r.status_code == 403, r.status_code
    return "Auditor yang mengubah status keputusan ditolak dengan HTTP 403."


# ---------------------------------------------------------------------------
# Modul D: korelasi hybrid dan pengelompokan isu
# ---------------------------------------------------------------------------
def tc_hyb_05(ctx):
    from backend.db.session import session_scope
    from backend.repositories import history as history_repo

    with session_scope(ctx.db_url) as s:
        history_repo.save_findings(s, "SAST-BB", history_repo.SAST_SCANNER, [{
            "key_id": "sonar-1", "cwe_id": "CWE-798", "component": "src/Config.php",
            "issue_description": "Hardcoded password", "predicted_cvss4_score": 6.79, "predicted_severity": "MEDIUM"}])
        history_repo.save_findings(s, "DAST-BB", history_repo.DAST_SCANNER, [{
            "key_id": "SQL Injection", "cwe_id": "CWE-89", "component": "GET https://app.uji/?id=1",
            "issue_description": "SQL injection may be possible.", "predicted_cvss4_score": 8.21,
            "predicted_severity": "HIGH"}])
    body = ctx.client.post("/api/v1/correlation/run", headers=ctx.auth("analyst"),
                           json={"sast_batch_id": "SAST-BB", "dast_batch_id": "DAST-BB"}).json()
    assert body["batch_id"] and len(body["records"]) == 0 and body["unpaired_count"] == 2, body
    items = ctx.client.post("/api/v1/dss/rank", json={"batch_id": body["batch_id"], "persist": False}).json()["items"]
    by_source = {it["source"]: it for it in items}
    assert set(by_source) == {"sast", "dast"}, by_source.keys()
    assert all(it["is_true_positive"] is False for it in items)
    assert by_source["dast"]["hybrid_score"] == 8.21 and by_source["sast"]["hybrid_score"] == 6.79
    return ("Tanpa irisan CWE, 0 pasangan dan 2 temuan pemindai tunggal tersimpan; keduanya muncul sebagai isu "
            "SAST saja dan DAST saja dengan skor tidak dieskalasi (8,21 dan 6,79).")


def tc_hyb_06(ctx):
    it = ctx.item("Cookie Without Secure Flag")
    assert it["pair_count"] == 2 and len(it["files"]) == 2 and len(it["endpoints"]) == 1, it
    assert it["hybrid_score"] == 7.30
    return "Dua pasangan dengan CWE-614 dan alert yang sama tergabung menjadi satu isu (2 berkas, 1 endpoint, skor 7,30)."


# ---------------------------------------------------------------------------
# Modul E: kelas prioritas dan pengurutan
# ---------------------------------------------------------------------------
def tc_pri_01(ctx):
    it = ctx.item("Cross Site Scripting (Reflected)")
    assert it["priority"] == "P1" and it["recommendation"]["rule_id"] == "R1", it["recommendation"]
    return "Isu CRITICAL yang terdeteksi kedua pemindai ditetapkan P1 melalui aturan R1."


def tc_pri_02(ctx):
    it = ctx.item("SQL Injection")
    assert it["priority"] == "P2" and it["recommendation"]["rule_id"] == "R3" and it["source"] == "dast"
    return "Isu HIGH yang hanya terdeteksi DAST ditetapkan P2 melalui aturan R3."


def tc_pri_03(ctx):
    it = ctx.item("Strict-Transport-Security Header Not Set")
    assert it["priority"] == "P3" and it["recommendation"]["rule_id"] == "R5"
    return "Isu MEDIUM ditetapkan P3 melalui aturan R5."


def tc_pri_04(ctx):
    order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
    ranks = [order[it["priority"]] for it in ctx.rank()["items"]]
    assert ranks == sorted(ranks), ranks
    return f"Urutan kelas pada daftar: {ranks}; seluruh isu P1 berada di atas P2, dan P2 di atas P3."


def tc_pri_05(ctx):
    first = [it["issue_code"] for it in ctx.rank()["items"]]
    second = [it["issue_code"] for it in ctx.rank()["items"]]
    assert first == second
    return f"Dua kali pengurutan pada masukan yang sama menghasilkan urutan identik ({len(first)} isu)."


def tc_pri_06(ctx):
    run = ctx.rank()
    assert run["normalization"] == "minmax", run["normalization"]
    r = ctx.client.post("/api/v1/dss/rank", json={"batch_id": SESSION_ID, "persist": True, "normalization": "vector"},
                        headers=ctx.auth("analyst"))
    assert r.status_code == 422, r.status_code
    return "Pengurutan mencatat normalisasi 'minmax'; what-if normalisasi vektor yang diminta disimpan ditolak (HTTP 422)."


# ---------------------------------------------------------------------------
# Modul F: rekomendasi dan SLA
# ---------------------------------------------------------------------------
def tc_rec_01(ctx):
    rec = ctx.item("Cross Site Scripting (Reflected)")["recommendation"]
    due = (datetime.date.today() + datetime.timedelta(days=7)).isoformat()
    assert rec["action"] == "REMEDIATE_NOW" and rec["sla_days"] == 7 and rec["sla_due_date"] == due, rec
    return f"Isu P1 direkomendasikan '{rec['action_label']}' dengan SLA 7 hari (tenggat {due})."


def tc_rec_02(ctx):
    it = ctx.item("Cross Site Scripting (Reflected)")
    exp = it["score_explanation"]
    assert it["why"] and "terdeteksi di kode" in it["why"], it["why"]
    assert exp["chain_text"] and "kedua scanner" in exp["chain_text"], exp["chain_text"]
    return f"Penjelasan memuat alasan prioritas dan rantai skor: \"{exp['chain_text']}\""


def tc_rec_03(ctx):
    it = ctx.item("SQL Injection")
    chain = it["score_explanation"]["chain_text"]
    assert chain.startswith("Hanya terdeteksi DAST") and "tanpa eskalasi" in chain, chain
    assert "hanya terdeteksi di aplikasi berjalan" in it["why"], it["why"]
    return f"Isu pemindai tunggal dijelaskan tanpa eskalasi: \"{chain}\""


# ---------------------------------------------------------------------------
# Modul G: tindak lanjut dan jejak audit
# ---------------------------------------------------------------------------
def tc_dec_01(ctx):
    key = ctx.item("Strict-Transport-Security Header Not Set")["decision_key"]
    codes = [ctx.client.put(f"/api/v1/decisions/{key}", headers=ctx.auth("analyst"), json={field: value}).status_code
             for field, value in (("asset_criticality", 0), ("asset_criticality", 6),
                                  ("remediation_effort", 0), ("remediation_effort", 6))]
    assert codes == [422] * 4, codes
    return "Dampak bisnis dan upaya perbaikan bernilai 0 dan 6 (di luar 1–5) ditolak dengan HTTP 422."


def tc_dec_02(ctx):
    key = ctx.item("SQL Injection")["decision_key"]
    r = ctx.client.put(f"/api/v1/decisions/{key}", headers=ctx.auth("manager"), json={"status": "ACCEPTED_RISK"})
    assert r.status_code == 422, r.status_code
    return "Status 'Risiko diterima' tanpa alasan ditolak dengan HTTP 422."


def tc_dec_03(ctx):
    key = ctx.item("Content Security Policy (CSP) Header Not Set")["decision_key"]
    r = ctx.client.put(f"/api/v1/decisions/{key}", headers=ctx.auth("manager"),
                       json={"status": "ACCEPTED_RISK", "reason": "Halaman statis tanpa skrip pihak ketiga"})
    assert r.status_code == 200, r.text[:200]
    events = ctx.client.get(f"/api/v1/decisions/{key}/events").json()["events"]
    accepted = [e for e in events if e["to_status"] == "ACCEPTED_RISK"]
    assert accepted and accepted[0]["actor"] == ROLE_USERS["manager"], events
    e = accepted[0]
    return (f"Manajer menerima risiko dengan alasan; peristiwa tercatat (pelaku {e['actor']}, "
            f"status {e['from_status']} → {e['to_status']}).")


def tc_dec_04(ctx):
    key = ctx.item("Cookie Without Secure Flag")["decision_key"]
    r = ctx.client.put(f"/api/v1/decisions/{key}", headers=ctx.auth("analyst"),
                       json={"chosen_action": "REMEDIATE_NOW", "owner": "tim-web", "sla_due_date": "2026-12-31"})
    assert r.status_code == 200, r.text[:200]
    ctx.rank(persist=True, role="analyst")
    dec = ctx.item("Cookie Without Secure Flag")["decision"]
    assert (dec["chosen_action"], dec["owner"], dec["sla_due_date"]) == ("REMEDIATE_NOW", "tim-web", "2026-12-31"), dec
    return "Prioritas, penanggung jawab, dan tenggat yang diisi analis tetap utuh setelah urutan dihitung ulang dan disimpan."


def tc_dec_05(ctx):
    key = ctx.item("SQL Injection")["decision_key"]
    r = ctx.client.put(f"/api/v1/decisions/{key}", headers=ctx.auth("developer"),
                       json={"status": "IN_PROGRESS", "reason": "Perbaikan query parameterized"})
    assert r.status_code == 200, r.text[:200]
    return "Pengembang memperbarui progres menjadi 'Sedang dikerjakan' (HTTP 200)."


# ---------------------------------------------------------------------------
# Modul H: pengaturan kebijakan, analisis sensitivitas, dan ekspor
# ---------------------------------------------------------------------------
def _config(ctx) -> dict:
    cfg = ctx.client.get("/api/v1/dss/config").json()
    return {k: v for k, v in cfg.items() if not k.startswith("_")}


def tc_cfg_01(ctx):
    cfg = _config(ctx)
    before = ctx.rank()["config_hash"]
    for c in cfg["criteria"]:
        if c["key"] == "remediation_effort":
            c["weight"] = 0.10
    r = ctx.client.put("/api/v1/dss/config", json=cfg, headers=ctx.auth("manager"))
    assert r.status_code == 200, r.text[:200]
    saved = {c["key"]: c["weight"] for c in _config(ctx)["criteria"]}
    after = ctx.rank()["config_hash"]
    assert saved["remediation_effort"] == 0.10 and after != before, (saved, before, after)
    return "Manajer mengubah bobot C7 menjadi 0,10; konfigurasi tersimpan dan sidik konfigurasi pada pengurutan berubah."


def tc_cfg_02(ctx):
    cfg = _config(ctx)
    cfg["criteria"][0]["weight"] = -0.2
    r = ctx.client.put("/api/v1/dss/config", json=cfg, headers=ctx.auth("manager"))
    assert r.status_code == 422, r.status_code
    return "Konfigurasi dengan bobot negatif ditolak dengan HTTP 422."


def tc_cfg_03(ctx):
    r = ctx.client.put("/api/v1/dss/config", json=_config(ctx), headers=ctx.auth("analyst"))
    assert r.status_code == 403, r.status_code
    return "Analis yang mengubah konfigurasi kebijakan ditolak dengan HTTP 403."


def tc_sen_01(ctx):
    body = ctx.client.post("/api/v1/dss/sensitivity", json={"batch_id": SESSION_ID, "k": 3}).json()
    n_criteria = len(ctx.rank()["criteria"])
    assert body["order_basis"] == "final" and len(body["variants"]) == 6 * n_criteria, body.keys()
    return (f"Sensitivitas bobot menghasilkan {len(body['variants'])} varian (6 langkah × {n_criteria} kriteria) "
            "pada urutan akhir.")


def tc_sen_02(ctx):
    body = ctx.client.post("/api/v1/dss/sensitivity/escalation-rate",
                           json={"batch_id": SESSION_ID, "rates": [0.0, 0.1, 0.2]}).json()
    rates = [v["escalation_rate"] for v in body["variants"]]
    base = [v for v in body["variants"] if v["escalation_rate"] == body["baseline_rate"]]
    assert rates == [0.0, 0.1, 0.2] and base and abs(base[0]["spearman_rho"] - 1.0) < 1e-9, body
    return "Sensitivitas escalation rate menghasilkan 3 varian; varian dasar (ER 0,10) identik dengan urutan dasar (ρ = 1)."


def tc_exp_02(ctx):
    r = ctx.client.get("/api/v1/decisions/export.xlsx", params={"batch_id": SESSION_ID}, headers=ctx.auth("auditor"))
    assert r.status_code == 200 and r.content[:2] == b"PK", r.status_code
    return f"Auditor mengunduh laporan tindak lanjut berformat Excel ({len(r.content)} bita)."


CASES = [
    Case("TC-AUTH-01", "A", "Login dengan kredensial valid", "Login sebagai Analis Keamanan, lalu buka profil.",
         "Nama pengguna dan kata sandi valid", "Token diterima dan peran pengguna dikenali.",
         "HTTP 200 dan peran 'analyst'.", tc_auth_01),
    Case("TC-AUTH-02", "A", "Login dengan kata sandi salah", "Login dengan kata sandi yang salah.",
         "Kata sandi tidak valid", "Login ditolak.", "HTTP 401.", tc_auth_02),
    Case("TC-AUTH-03", "A", "Menyimpan prioritas tanpa login", "Simpan hasil prioritas tanpa login.",
         "Permintaan penyimpanan tanpa token", "Penyimpanan ditolak.", "HTTP 401.", tc_auth_03),
    Case("TC-AUTH-04", "A", "Pengembang menyimpan prioritas", "Login sebagai Pengembang, lalu simpan hasil prioritas.",
         "Token peran Pengembang", "Penyimpanan ditolak karena peran tidak berhak.", "HTTP 403.", tc_auth_04),
    Case("TC-AUTH-05", "A", "Analis menerima risiko", "Login sebagai Analis, lalu tetapkan status 'Risiko diterima'.",
         "Status ACCEPTED_RISK beserta alasan", "Perubahan ditolak karena hanya Manajer yang berhak.", "HTTP 403.",
         tc_auth_05),
    Case("TC-AUTH-06", "A", "Auditor mengubah keputusan", "Login sebagai Auditor, lalu ubah status isu.",
         "Status IN_PROGRESS", "Perubahan ditolak karena Auditor hanya membaca.", "HTTP 403.", tc_auth_06),
    Case("TC-HYB-05", "D", "Temuan tanpa pasangan CWE", "Jalankan korelasi pada sesi SAST dan DAST tanpa irisan CWE.",
         "SAST CWE-798 (6,79) dan DAST CWE-89 (8,21)",
         "Temuan disimpan sebagai temuan pemindai tunggal dan muncul sebagai isu tanpa eskalasi skor.",
         "0 pasangan, 2 temuan tunggal, isu SAST saja dan DAST saja dengan skor asli.", tc_hyb_05),
    Case("TC-HYB-06", "D", "Pengelompokan pasangan menjadi isu", "Buka daftar prioritas sesi uji.",
         "Dua pasangan CWE-614 dengan alert yang sama pada dua berkas",
         "Kedua pasangan tergabung menjadi satu isu dengan skor pasangan tertinggi.",
         "1 isu, 2 berkas, 1 endpoint, skor 7,30.", tc_hyb_06),
    Case("TC-PRI-01", "E", "Penetapan P1", "Buka daftar prioritas sesi uji.",
         "Isu CRITICAL (9,37) yang terdeteksi kedua pemindai", "Isu ditetapkan P1.", "P1 melalui aturan R1.",
         tc_pri_01),
    Case("TC-PRI-02", "E", "Penetapan P2 untuk isu satu pemindai", "Buka daftar prioritas sesi uji.",
         "Isu HIGH (8,21) yang hanya terdeteksi DAST", "Isu ditetapkan P2.", "P2 melalui aturan R3.", tc_pri_02),
    Case("TC-PRI-03", "E", "Penetapan P3", "Buka daftar prioritas sesi uji.", "Isu MEDIUM (6,72)",
         "Isu ditetapkan P3.", "P3 melalui aturan R5.", tc_pri_03),
    Case("TC-PRI-04", "E", "Urutan antarkelas", "Buka daftar prioritas sesi uji.", "Isu dari kelas P1, P2, dan P3",
         "Isu kelas lebih mendesak selalu berada di atas.", "Urutan kelas tidak pernah menurun.", tc_pri_04),
    Case("TC-PRI-05", "E", "Urutan deterministik", "Hitung urutan dua kali tanpa mengubah masukan.",
         "Sesi dan konfigurasi yang sama", "Kedua urutan identik.", "Daftar kode isu identik.", tc_pri_05),
    Case("TC-PRI-06", "E", "Normalisasi TOPSIS dan what-if",
         "Hitung urutan, lalu coba simpan urutan dengan normalisasi vektor.",
         "Konfigurasi bawaan; permintaan normalisasi 'vector' dengan persist=true",
         "Normalisasi min-max tercatat; what-if tidak dapat disimpan.", "'minmax' dan HTTP 422.", tc_pri_06),
    Case("TC-REC-01", "F", "Tindakan dan tenggat SLA", "Buka rekomendasi isu P1.", "Isu P1, SLA 'Perbaiki segera' 7 hari",
         "Tindakan 'Perbaiki segera' dengan tenggat 7 hari dari hari ini.", "Aksi REMEDIATE_NOW dan tenggat tepat.",
         tc_rec_01),
    Case("TC-REC-02", "F", "Penjelasan rekomendasi", "Buka penjelasan isu P1.", "Isu hybrid CRITICAL",
         "Penjelasan memuat alasan prioritas dan rantai skor dengan eskalasi.",
         "Alasan menyebut deteksi di kode; rantai skor menyebut kedua scanner.", tc_rec_02),
    Case("TC-REC-03", "F", "Penjelasan isu pemindai tunggal", "Buka penjelasan isu SQL injection.",
         "Isu DAST saja", "Rantai skor menyatakan hanya terdeteksi DAST dan tanpa eskalasi.",
         "Teks rantai skor dan alasan sesuai sumber deteksi.", tc_rec_03),
    Case("TC-DEC-01", "G", "Validasi dampak bisnis dan upaya", "Isi dampak bisnis dan upaya di luar rentang.",
         "Nilai 0 dan 6", "Masukan ditolak.", "HTTP 422 untuk keempat masukan.", tc_dec_01),
    Case("TC-DEC-02", "G", "Risiko diterima tanpa alasan", "Login sebagai Manajer, tetapkan 'Risiko diterima' tanpa alasan.",
         "Status ACCEPTED_RISK tanpa alasan", "Perubahan ditolak karena status wajib beralasan.", "HTTP 422.",
         tc_dec_02),
    Case("TC-DEC-03", "G", "Penerimaan risiko tercatat", "Login sebagai Manajer, terima risiko beserta alasan, buka riwayat.",
         "Status ACCEPTED_RISK beserta alasan", "Keputusan tersimpan dan peristiwa tercatat pada jejak audit.",
         "HTTP 200; peristiwa memuat pelaku serta status sebelum dan sesudah.", tc_dec_03),
    Case("TC-DEC-04", "G", "Keputusan analis tidak ditimpa", "Isi prioritas, penanggung jawab, dan tenggat; hitung ulang urutan.",
         "Prioritas P1, penanggung jawab 'tim-web', tenggat 2026-12-31",
         "Kolom milik analis tidak berubah setelah urutan disimpan ulang.", "Ketiga nilai tetap sama.", tc_dec_04),
    Case("TC-DEC-05", "G", "Pengembang memperbarui progres", "Login sebagai Pengembang, ubah status menjadi 'Sedang dikerjakan'.",
         "Status IN_PROGRESS beserta catatan", "Progres tersimpan.", "HTTP 200.", tc_dec_05),
    Case("TC-CFG-01", "H", "Manajer mengubah bobot", "Login sebagai Manajer, ubah bobot C7, simpan, lalu hitung urutan.",
         "Bobot C7 = 0,10", "Konfigurasi tersimpan dan hasil pengurutan mencatat sidik konfigurasi baru.",
         "HTTP 200; bobot tersimpan; sidik konfigurasi berubah.", tc_cfg_01),
    Case("TC-CFG-02", "H", "Validasi bobot", "Login sebagai Manajer, simpan konfigurasi dengan bobot negatif.",
         "Bobot −0,2", "Konfigurasi ditolak.", "HTTP 422.", tc_cfg_02),
    Case("TC-CFG-03", "H", "Analis mengubah kebijakan", "Login sebagai Analis, simpan konfigurasi.",
         "Konfigurasi yang sama", "Penyimpanan ditolak karena hanya Manajer yang berhak.", "HTTP 403.", tc_cfg_03),
    Case("TC-SEN-01", "H", "Sensitivitas bobot", "Jalankan analisis sensitivitas bobot pada sesi uji.",
         "Langkah ±10%, ±20%, ±30%", "Satu varian untuk setiap langkah dan kriteria, diukur pada urutan akhir.",
         "Jumlah varian = 6 × jumlah kriteria; basis urutan 'final'.", tc_sen_01),
    Case("TC-SEN-02", "H", "Sensitivitas escalation rate", "Jalankan analisis sensitivitas ER pada sesi uji.",
         "ER 0,00; 0,10; 0,20", "Satu varian per nilai ER; varian dasar identik dengan urutan dasar.",
         "3 varian; ρ = 1 pada ER 0,10.", tc_sen_02),
    Case("TC-EXP-02", "H", "Ekspor laporan tindak lanjut", "Login sebagai Auditor, unduh laporan tindak lanjut.",
         "Sesi uji", "Berkas Excel terunduh.", "HTTP 200 dan berkas berformat XLSX.", tc_exp_02),
]


def run_dss_cases() -> list[dict]:
    """Menjalankan seluruh kasus DSS dan mengembalikan baris hasil berformat sama dengan halaman Pengujian Black-Box."""
    rows = []
    with dss_harness() as ctx:
        for case in CASES:
            t0 = time.time()
            try:
                actual, status, note = case.run(ctx), "PASS", "Pengujian berhasil dan memenuhi kriteria."
            except Exception as e:  # kegagalan satu kasus tidak menghentikan kasus lain
                actual, status, note = f"Gagal: {e}", "FAIL", f"Exception: {type(e).__name__}"
            rows.append({
                "ID Kasus": case.case_id, "Modul": MODULE_LABELS[case.module], "Fitur / Skenario Uji": case.title,
                "Langkah Pengujian": case.steps, "Masukan (Input)": case.given,
                "Hasil yang Diharapkan": case.expected, "Kriteria Keberhasilan": case.criteria,
                "Hasil Aktual": actual, "Status": status, "Durasi (ms)": round((time.time() - t0) * 1000, 2),
                "Catatan": note,
            })
    return rows
