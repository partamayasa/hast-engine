# tests/test_ops_tools.py
"""Alat operasional: cadangan daring SQLite dengan retensi, dan lembar verifikasi korelasi hybrid."""
import importlib.util
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("hast_backup_tool", ROOT / "tools" / "backup_db" / "app.py")
backup_tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(backup_tool)
_vspec = importlib.util.spec_from_file_location("hast_verification_tool",
                                                ROOT / "tools" / "hybrid_verification" / "app.py")
verif = importlib.util.module_from_spec(_vspec)
_vspec.loader.exec_module(verif)
_cspec = importlib.util.spec_from_file_location("hast_cwe_profile_tool",
                                                ROOT / "tools" / "cwe_profile_sensitivity" / "app.py")
cwe_tool = importlib.util.module_from_spec(_cspec)
_cspec.loader.exec_module(cwe_tool)


def _weakness(*codes):
    return {"description": [{"lang": "en", "value": c} for c in codes] + [{"lang": "es", "value": "CWE-0"}]}


def test_cwe_profile_rules_select_expected_codes():
    entry = [_weakness("CWE-79", "CWE-80"), {"description": []}, _weakness("CWE-89", "CWE-79")]
    assert cwe_tool.codes_by_rule(entry, "last") == ["CWE-89"]
    assert cwe_tool.codes_by_rule(entry, "first") == ["CWE-79"]
    assert cwe_tool.codes_by_rule(entry, "all") == ["CWE-79", "CWE-80", "CWE-89"]
    assert cwe_tool.codes_by_rule([], "first") == []


def test_cwe_profile_last_rule_matches_dataset_collector_and_profiler(tmp_path):
    """Aturan 'last' dan agregasinya sama dengan dataset_collector.py dan cwe_profiler.py."""
    import pandas as pd
    dataset = pd.DataFrame([
        {"cve_id": "CVE-1", "cvss_score": 8.0, "cwe_code": "CWE-89", "summary": "a", "attack_vector": "NETWORK"},
        {"cve_id": "CVE-2", "cvss_score": 6.0, "cwe_code": "CWE-89", "summary": "b", "attack_vector": "NETWORK"},
        {"cve_id": "CVE-3", "cvss_score": 2.0, "cwe_code": "CWE-79", "summary": "c", "attack_vector": "LOCAL"}])
    weaknesses = {"CVE-1": [_weakness("CWE-79"), _weakness("CWE-89")], "CVE-2": [_weakness("CWE-89", "CWE-79")],
                  "CVE-3": [_weakness("CWE-79")]}
    last = cwe_tool.build_profile(dataset, weaknesses, "last").set_index("cwe_code")
    assert last.loc["CWE-89", "cvss_score"] == 7.0 and last.loc["CWE-89", "attack_vector"] == "NETWORK"
    assert last.loc["CWE-79", "cvss_score"] == 2.0
    every = cwe_tool.build_profile(dataset, weaknesses, "all").set_index("cwe_code")
    assert round(every.loc["CWE-79", "cvss_score"], 4) == round((8 + 6 + 2) / 3, 4)


def test_cwe_profile_tool_works_on_copy_and_restores_lookup(tmp_path):
    import pytest
    db = tmp_path / "sumber.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE t (x INTEGER)")
    con.commit()
    con.close()
    before, original = db.read_bytes(), cwe_tool.service.crit.load_cwe_lookup
    with cwe_tool.database_copy(db) as url:
        copied = Path(url.replace("sqlite:///", "", 1))
        assert copied.exists() and copied != db
    assert not copied.exists() and db.read_bytes() == before
    with pytest.raises(RuntimeError), cwe_tool.lookup_override(tmp_path / "x.csv"):
        raise RuntimeError
    assert cwe_tool.service.crit.load_cwe_lookup is original


def test_backup_creates_consistent_copy_and_prunes(tmp_path):
    db = tmp_path / "src.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE t (x INTEGER)")
    con.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(100)])
    con.commit()
    con.close()

    out = tmp_path / "bk"
    first = backup_tool.backup(db, out)
    (out / "database-auto-20000101-000000.db").write_bytes(first.read_bytes())  # cadangan yang lebih lama
    removed = backup_tool.prune(out, keep=1)

    assert [p.name for p in removed] == ["database-auto-20000101-000000.db"]
    check = sqlite3.connect(first)
    assert check.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 100
    check.close()


def test_hybrid_verification_sheet_roundtrip(tmp_path):
    import openpyxl
    from backend.repositories.history import HYBRID_SCANNER, SINGLE_SCANNER

    def pair(key, file, ep):
        return {"key_id": key, "scanner_type": HYBRID_SCANNER, "cwe_id": "CWE-614", "dast_key_id": "Cookie",
                "sast_component": file, "dast_component": ep, "sast_key_id": f"k-{key}", "predicted_score": 7.0,
                "base_score": 6.5, "is_true_positive": True, "sast_score": 6.4, "dast_score": 6.6}
    rows = [pair("P1", "a.php", "GET https://x/"), pair("P2", "b.php", "GET https://x/"),
            {"key_id": "S1", "scanner_type": SINGLE_SCANNER, "cwe_id": "CWE-89", "dast_key_id": "SQLi",
             "sast_component": "", "dast_component": "GET https://x/?q", "predicted_score": 8.2}]
    sheet = verif.build_sheet_rows(rows, {"k-P1": {"line": 12, "rule": "php:S2092"}}, {})
    assert [r["Pair ID"] for r in sheet] == ["P1", "P2"]  # temuan tunggal tidak ikut diverifikasi
    assert sheet[0]["Baris"] == 12 and sheet[0]["Aturan Sonar"] == "php:S2092"

    path = tmp_path / "v.xlsx"
    verif.write_workbook(str(path), "HAST-X", sheet)
    wb = openpyxl.load_workbook(path)
    ws = wb[verif.SHEET_PAIRS]
    headers = [c.value for c in ws[1]]
    ws.cell(row=2, column=headers.index(verif.VERDICT_COL) + 1, value="Ya")
    ws.cell(row=2, column=headers.index("Alasan") + 1, value="cookie diatur di a.php")
    ws.cell(row=3, column=headers.index(verif.VERDICT_COL) + 1, value="Tidak")
    wb.save(path)

    result = verif.summarize(str(path))
    assert result["overall"]["ya"] == 1 and result["overall"]["tidak"] == 1
    assert result["overall"]["precision"] == 0.5 and result["rows_without_reason"] == ["2"]
    assert verif.wilson_interval(0, 0) is None


def test_followup_import_reads_only_assigned_columns(tmp_path):
    import openpyxl
    spec = importlib.util.spec_from_file_location("hast_followup_import", ROOT / "tools" / "dss_followup_import" / "app.py")
    imp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(imp)
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = imp.SHEET
    ws.append(["Kode isu", "Usulan C6", "Usulan C7", imp.C6_COL, imp.C7_COL, imp.KEY_COL])
    ws.append(["ISU-A", 5, 1, 4, 2, "key-a"])        # ditetapkan berbeda dari usulan
    ws.append(["ISU-B", 3, 1, None, None, "key-b"])  # hanya usulan: tidak diterapkan
    ws.append(["ISU-C", 2, 2, 3, None, "key-c"])     # hanya C6
    path = tmp_path / "c6c8.xlsx"
    wb.save(path)
    changes = imp.read_payloads(str(path))
    assert [c["issue_code"] for c in changes] == ["ISU-A", "ISU-C"]
    assert changes[0]["payload"] == {"asset_criticality": 4, "remediation_effort": 2}
    assert changes[1]["payload"] == {"asset_criticality": 3}
    # Lembar lama dengan kolom "C8 ditetapkan" tetap terbaca.
    ws.cell(row=1, column=5, value="C8 ditetapkan")
    wb.save(path)
    assert imp.read_payloads(str(path))[0]["payload"] == {"asset_criticality": 4, "remediation_effort": 2}
    ws.cell(row=2, column=4, value=6)
    wb.save(path)
    try:
        imp.read_payloads(str(path))
        raise AssertionError("nilai 6 seharusnya ditolak")
    except ValueError as e:
        assert "1–5" in str(e)
