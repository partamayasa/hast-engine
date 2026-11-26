# frontend/components/blackbox_core.py
"""
Pemeriksaan Black-Box untuk fungsi pengolahan temuan (modul B, C, D, dan H) yang benar-benar memanggil sistem.

Setiap fungsi menerima `Context` dari `blackbox_dss.dss_harness` (TestClient, token per peran, basis data sementara),
mengirim masukan, dan membandingkan keluarannya. Dipakai oleh halaman Pengujian Black-Box dan oleh
tests/test_blackbox_scenarios.py, sehingga keduanya menguji hal yang sama.
"""
import io
import json
import os

import pandas as pd

from backend.config import ROOT_DIR

SAMPLE_SONAR_PATH = os.path.join(ROOT_DIR, "sample-reports", "SonarQube_Report.json")
SAMPLE_ZAP_PATH = os.path.join(ROOT_DIR, "sample-reports", "OWASP_ZAP_Report.json")


def _ingest(ctx, scanner: str, name: str, content: bytes, mime: str = "application/json"):
    return ctx.client.post(f"/api/v1/ingest/{scanner}", files={"file": (name, content, mime)}, headers=ctx.auth("analyst"))


def _zap_report(*alerts: dict) -> bytes:
    return json.dumps({"site": [{"@name": "https://app.uji", "alerts": list(alerts)}]}).encode("utf-8")


def _zap_alert(name: str, cweid, uri: str = "https://app.uji/") -> dict:
    return {"alert": name, "cweid": cweid, "desc": "<p>Uji</p>", "solution": "<p>Uji</p>",
            "instances": [{"method": "GET", "uri": uri}]}


def check_sonar_report_is_parsed(ctx) -> str:
    with open(SAMPLE_SONAR_PATH, "rb") as f:
        r = _ingest(ctx, "sonarqube", "SonarQube_Report.json", f.read())
    assert r.status_code == 200, f"HTTP {r.status_code}"
    records = r.json()["records"]
    assert records and r.json()["count"] == len(records)
    for rec in records:
        assert rec["key_id"] and rec["component"] and rec["issue_description"]
        assert rec["cwe_id"] == "N/A" or rec["cwe_id"].startswith("CWE-"), rec["cwe_id"]
    return f"{len(records)} temuan keamanan diekstrak beserta kunci, komponen, pesan, dan CWE."


def check_non_json_is_rejected(ctx) -> str:
    samples = {"sample.csv": b"key,message\nK1,uji\n", "document.pdf": b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n",
               "report.xml": b"<?xml version='1.0'?><report/>", "data.txt": b"bukan json"}
    for name, content in samples.items():
        for scanner in ("sonarqube", "zap"):
            r = _ingest(ctx, scanner, name, content, "application/octet-stream")
            assert r.status_code == 400, f"{scanner} {name}: HTTP {r.status_code}"
    return f"Berkas {', '.join(samples)} ditolak dengan HTTP 400 pada kedua endpoint unggah."


def check_upload_size_limit(ctx) -> str:
    from backend.core.settings import get_settings

    limit = get_settings().max_upload_mb * 1024 * 1024
    over = _ingest(ctx, "sonarqube", "besar.json", b" " * (limit + 1))
    assert over.status_code == 413, f"Di atas batas: HTTP {over.status_code}"
    # Tepat pada batas tidak ditolak karena ukuran (isinya tetap bukan JSON, sehingga HTTP 400).
    at = _ingest(ctx, "sonarqube", "batas.json", b" " * limit)
    assert at.status_code == 400, f"Tepat pada batas: HTTP {at.status_code}"
    return f"Berkas {get_settings().max_upload_mb} MB + 1 bita ditolak dengan HTTP 413; berkas tepat pada batas tidak ditolak karena ukuran."


def check_zap_report_is_parsed(ctx) -> str:
    with open(SAMPLE_ZAP_PATH, "rb") as f:
        r = _ingest(ctx, "zap", "OWASP_ZAP_Report.json", f.read())
    assert r.status_code == 200, f"HTTP {r.status_code}"
    records = r.json()["records"]
    assert records
    for rec in records:
        assert rec["cwe_id"] == "N/A" or rec["cwe_id"].removeprefix("CWE-").isdigit(), rec["cwe_id"]
        assert rec["component"].split(" ")[0] in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}, rec["component"]
    return f"{len(records)} peringatan diekstrak beserta CWE, metode HTTP, dan URI."


def check_invalid_cwe_becomes_na(ctx) -> str:
    invalid = ["-1", -1, "0", 0, "", None, "-7", "abc"]
    r = _ingest(ctx, "zap", "zap.json", _zap_report(*[_zap_alert(f"A{i}", v) for i, v in enumerate(invalid)],
                                                  _zap_alert("Kontrol", "79")))
    assert r.status_code == 200, f"HTTP {r.status_code}"
    got = {rec["key_id"]: rec["cwe_id"] for rec in r.json()["records"]}
    wrong = {repr(v): got[f"A{i}"] for i, v in enumerate(invalid) if got[f"A{i}"] != "N/A"}
    assert not wrong, f"cweid tidak menjadi N/A: {wrong}"
    assert got["Kontrol"] == "CWE-79", got["Kontrol"]
    return f"{len(invalid)} nilai cweid tidak sah (negatif, nol, kosong, null, teks) menjadi N/A; cweid 79 tetap CWE-79."


def check_out_of_scope_is_filtered(ctx) -> str:
    r = _ingest(ctx, "zap", "zap.json", _zap_report(_zap_alert("Luar", "79", "https://support.mozilla.org/kb/sample"),
                                                  _zap_alert("Dalam", "79", "https://app.uji/kb")))
    assert r.status_code == 200, f"HTTP {r.status_code}"
    names = [rec["key_id"] for rec in r.json()["records"]]
    assert names == ["Dalam"], names
    return "Peringatan pada support.mozilla.org disaring, sedangkan peringatan pada domain uji dipertahankan."


class _FixedModel:
    def __init__(self, value: float):
        self.value = value

    def predict(self, _x):
        return [self.value]


def check_score_is_clipped(ctx) -> str:
    """Keluaran model diganti nilai di luar rentang agar batas 0-10 pada /predict benar-benar teruji."""
    from backend import model_loader

    original = model_loader.rf_model
    cases = {-3.0: 0.0, -0.01: 0.0, 0.0: 0.0, 5.5: 5.5, 10.0: 10.0, 10.01: 10.0, 15.0: 10.0}
    try:
        for raw, expected in cases.items():
            model_loader.rf_model = _FixedModel(raw)
            r = ctx.client.post("/predict", json={"scanner_type": "SonarQube", "description": "uji", "component": "a.php"})
            assert r.status_code == 200, f"HTTP {r.status_code}"
            assert r.json()["predicted_cvss4_score"] == expected, (raw, r.json())
    finally:
        model_loader.rf_model = original
    return "Keluaran model -3; -0,01; 10,01; dan 15 dibatasi menjadi 0,0 atau 10,0 pada respons /predict."


def check_empty_description_is_rejected(ctx) -> str:
    for text in ("", "   ", "\n\t"):
        r = ctx.client.post("/predict", json={"scanner_type": "SAST", "description": text, "component": "a.php"})
        assert r.status_code == 400, f"{text!r}: HTTP {r.status_code}"
        assert "kosong" in r.json()["detail"].lower()
    return "Deskripsi kosong, spasi, dan baris baru ditolak dengan HTTP 400."


def check_correlation_requires_both_sessions(ctx) -> str:
    from backend.db.session import session_scope
    from backend.repositories import history as history_repo

    row = {"key_id": "K", "cwe_id": "CWE-79", "component": "a", "issue_description": "uji", "predicted_cvss4_score": 5.0,
           "predicted_severity": "MEDIUM"}
    with session_scope(ctx.db_url) as s:
        history_repo.save_findings(s, "DAST-BB-PRASYARAT", history_repo.DAST_SCANNER, [row])
        history_repo.save_findings(s, "SAST-BB-PRASYARAT", history_repo.SAST_SCANNER, [row])
    for sast, dast in (("SAST-TIDAK-ADA", "DAST-BB-PRASYARAT"), ("SAST-BB-PRASYARAT", "DAST-TIDAK-ADA"),
                       ("SAST-TIDAK-ADA", "DAST-TIDAK-ADA")):
        for path in ("preview", "run"):
            r = ctx.client.post(f"/api/v1/correlation/{path}", json={"sast_batch_id": sast, "dast_batch_id": dast},
                                headers=ctx.auth("analyst"))
            assert r.status_code == 404, f"{path} {sast}/{dast}: HTTP {r.status_code}"
    ok = ctx.client.post("/api/v1/correlation/preview", json={"sast_batch_id": "SAST-BB-PRASYARAT",
                                                              "dast_batch_id": "DAST-BB-PRASYARAT"})
    assert ok.status_code == 200 and ok.json()["count"] == 1, ok.text[:200]
    return "Korelasi tanpa sesi SAST, tanpa sesi DAST, atau tanpa keduanya ditolak (HTTP 404); dengan kedua sesi berjalan."


def _delete_dialog_app():
    import streamlit as st

    from frontend.components import dialogs

    dialogs.can = lambda _permission: True
    dialogs.delete_batch = lambda batch_id: st.session_state.__setitem__("dihapus", batch_id)
    # Isi dialog dijalankan langsung; pembungkus st.dialog hanya mengatur tampilannya sebagai jendela modal.
    dialogs.confirm_delete_batch_dialog.__wrapped__("SAST-UJI")


def check_delete_needs_confirmation(ctx) -> str:
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_function(_delete_dialog_app, default_timeout=60).run()
    assert not at.exception, at.exception
    assert "Apakah anda yakin" in at.warning[0].value and [b.label for b in at.button] == ["Ya, Hapus Session", "Batal"]
    assert "dihapus" not in at.session_state
    at.button[1].click().run()
    assert "dihapus" not in at.session_state, "Tombol Batal menghapus sesi."
    at.button[0].click().run()
    assert at.session_state["dihapus"] == "SAST-UJI"

    from backend.db.session import session_scope
    from backend.repositories import history as history_repo
    with session_scope(ctx.db_url) as s:
        history_repo.save_findings(s, "SAST-BB-HAPUS", history_repo.SAST_SCANNER, [
            {"key_id": "K", "cwe_id": "CWE-79", "component": "a", "issue_description": "uji",
             "predicted_cvss4_score": 5.0, "predicted_severity": "MEDIUM"}])
    assert ctx.client.delete("/api/v1/batches/SAST-BB-HAPUS").status_code == 401
    assert ctx.client.delete("/api/v1/batches/SAST-BB-HAPUS", headers=ctx.auth("analyst")).status_code == 403
    assert len(ctx.client.get("/api/v1/batches/SAST-BB-HAPUS").json()["rows"]) == 1
    return ("Sesi tidak terhapus sebelum tombol Ya ditekan atau setelah Batal; permintaan hapus tanpa login (HTTP 401) dan "
            "oleh Analis (HTTP 403) ditolak, dan datanya tetap ada.")


def check_csv_export_matches_queue(ctx) -> str:
    from frontend.components.page_priority import _queue_frame

    items = ctx.rank()["items"]
    text = _queue_frame(items, {"OPEN": "Belum ditangani"}).to_csv(index=False)
    back = pd.read_csv(io.StringIO(text))
    assert len(back) == len(items)
    assert back["Kode"].tolist() == [it["issue_code"] for it in items]
    assert back["Urutan"].tolist() == [it["rank"] for it in items]
    missing = {"Prioritas", "Issue", "CWE", "Terdeteksi", "Severity", "Tindakan", "Due date", "Status"} - set(back.columns)
    assert not missing, missing
    return f"CSV daftar prioritas memuat {len(back)} isu dengan urutan dan kode yang sama seperti hasil pengurutan."
