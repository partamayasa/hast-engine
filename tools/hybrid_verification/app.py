#!/usr/bin/env python3
"""
tools/hybrid_verification/app.py

Verifikasi manual korelasi hybrid oleh peneliti. Korelasi memasangkan setiap temuan SonarQube dengan setiap
alert OWASP ZAP yang CWE-nya sama, tanpa memeriksa kesesuaian komponen. Alat ini menyiapkan lembar periksa
agar peneliti menilai, untuk setiap pasangan, apakah berkas kode dan endpoint tersebut benar-benar satu akar
masalah, lalu menghitung presisi korelasi berbasis CWE dari lembar yang sudah diisi.

Penilaian ini dilakukan oleh peneliti dan dilaporkan sebagai pemeriksaan peneliti, bukan penilaian pakar.

Pemakaian:
    uv run python tools/hybrid_verification/app.py generate --batch-id HAST-1795409398
    uv run python tools/hybrid_verification/app.py generate --batch-id HAST-1795409398 \\
        --sonar-report laporan_sonar.json --zap-report laporan_zap.json
    uv run python tools/hybrid_verification/app.py summarize tools/data/verifikasi_hybrid_HAST-1795409398.xlsx \\
        [--out tools/data/verifikasi_hybrid_ringkasan.json]

Laporan asli bersifat opsional; bila diberikan, lembar periksa diperkaya dengan nomor baris, aturan Sonar,
parameter, dan bukti respons ZAP.
"""
import argparse
import json
import math
import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import pandas as pd  # noqa: E402

from backend.db.bootstrap import init_database  # noqa: E402
from backend.db.session import session_scope  # noqa: E402
from backend.dss.issues import aggregate_issues  # noqa: E402
from backend.repositories import history as history_repo  # noqa: E402

SHEET_PAIRS = "Pasangan"
SHEET_GUIDE = "Petunjuk"
SHEET_SUMMARY = "Ringkasan"
VERDICT_COL = "Satu akar masalah?"
VERDICTS = ("Ya", "Tidak", "Tidak pasti")
EVIDENCE_MAX = 300

GUIDE_ROWS = [
    ("Tujuan", "Menilai apakah setiap pasangan hybrid (berkas SonarQube × endpoint OWASP ZAP dengan CWE sama) "
               "benar-benar menunjuk satu akar masalah. Hasilnya dipakai untuk menghitung presisi korelasi "
               "berbasis CWE pada BAB IV."),
    ("Status penilai", "Pemeriksaan dilakukan oleh peneliti dan dilaporkan sebagai pemeriksaan peneliti, bukan "
                       "penilaian pakar."),
    ("Ya", "Kode pada berkas SAST ikut menghasilkan respons endpoint DAST dengan kelemahan yang sama, sehingga "
           "memperbaiki kode tersebut diperkirakan menghilangkan alert ZAP pada endpoint itu."),
    ("Tidak", "Berkas SAST tidak terlibat dalam respons endpoint DAST, atau kelemahannya berbeda walaupun CWE-nya "
              "sama (misalnya cookie yang berbeda, atau header yang diatur di tempat lain)."),
    ("Tidak pasti", "Informasi tidak cukup untuk memutuskan. Tuliskan informasi yang kurang pada kolom Alasan."),
    ("Cara memeriksa SAST", "Buka isu di SonarQube memakai kolom 'Kunci isu Sonar' (halaman Issues, filter "
                            "menurut key), atau buka berkasnya di repositori kode aplikasi target."),
    ("Cara memeriksa DAST", "Buka endpoint pada kolom 'Endpoint DAST' dan periksa respons sesuai alert ZAP, atau "
                            "lihat kolom 'Bukti ZAP' bila laporan asli tersedia."),
    ("Aturan pengisian", "Isi kolom 'Satu akar masalah?' dengan Ya, Tidak, atau Tidak pasti. Kolom Alasan wajib "
                         "diisi untuk setiap baris agar penilaian dapat ditelusuri. Jangan mengubah kolom lain."),
]


def _load_json(path: str) -> dict:
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def sonar_index(path: str | None) -> dict[str, dict]:
    """Mengembalikan {kunci isu Sonar: {line, rule}} dari laporan JSON SonarQube."""
    if not path:
        return {}
    data = _load_json(path)
    out = {}
    for i in data.get("issues", []):
        line = i.get("line") or (i.get("textRange") or {}).get("startLine")
        out[str(i.get("key"))] = {"line": line, "rule": i.get("rule")}
    return out


def zap_index(path: str | None) -> dict[tuple[str, str], dict]:
    """Mengembalikan {(nama alert, 'METHOD uri'): {param, evidence, attack}} dari laporan JSON OWASP ZAP."""
    if not path:
        return {}
    data = _load_json(path)
    sites = data.get("site", [])
    sites = sites if isinstance(sites, list) else [sites]
    out = {}
    for site in sites:
        for alert in site.get("alerts", []):
            name = str(alert.get("alert") or alert.get("name") or "")
            for inst in alert.get("instances", []):
                endpoint = f"{inst.get('method', '')} {inst.get('uri', '')}".strip()
                out.setdefault((name, endpoint), {
                    "param": inst.get("param") or "",
                    "evidence": str(inst.get("evidence") or "")[:EVIDENCE_MAX],
                    "attack": str(inst.get("attack") or "")[:EVIDENCE_MAX],
                })
    return out


def build_sheet_rows(rows: list[dict], sonar: dict, zap: dict) -> list[dict]:
    """Menyusun satu baris lembar periksa untuk setiap pasangan hybrid, dikelompokkan menurut isu."""
    pairs = [r for r in rows if r.get("scanner_type") == history_repo.HYBRID_SCANNER]
    by_pair = {r["key_id"]: r for r in pairs}
    out = []
    for issue in sorted(aggregate_issues(pairs), key=lambda i: (-i["predicted_score"], i["key_id"])):
        for pair_id in issue["pair_ids"]:
            r = by_pair[pair_id]
            s_meta = sonar.get(str(r.get("sast_key_id")), {})
            z_meta = zap.get((str(r.get("dast_key_id")), str(r.get("dast_component"))), {})
            out.append({
                "No": len(out) + 1,
                "Isu": issue["key_id"],
                "Judul isu": issue["title"],
                "CWE": r.get("cwe_id"),
                "Pair ID": pair_id,
                "Berkas SAST": r.get("sast_component"),
                "Baris": s_meta.get("line") or "",
                "Aturan Sonar": s_meta.get("rule") or "",
                "Pesan SonarQube": r.get("sast_description") or "",
                "Kunci isu Sonar": r.get("sast_key_id"),
                "Endpoint DAST": r.get("dast_component"),
                "Alert ZAP": r.get("dast_key_id"),
                "Parameter ZAP": z_meta.get("param", ""),
                "Bukti ZAP": z_meta.get("evidence", ""),
                "Skor SAST": r.get("sast_score"),
                "Skor DAST": r.get("dast_score"),
                VERDICT_COL: "",
                "Alasan": "",
            })
    return out


def write_workbook(path: str, batch_id: str, sheet_rows: list[dict]) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation

    wb = Workbook()
    guide = wb.active
    guide.title = SHEET_GUIDE
    guide.append(["Lembar periksa korelasi hybrid", f"Sesi {batch_id}"])
    guide["A1"].font = Font(bold=True, size=13)
    guide.append([])
    for k, v in GUIDE_ROWS:
        guide.append([k, v])
    guide.column_dimensions["A"].width = 22
    guide.column_dimensions["B"].width = 110
    for row in guide.iter_rows(min_row=3):
        row[0].font = Font(bold=True)
        row[1].alignment = Alignment(wrap_text=True, vertical="top")

    ws = wb.create_sheet(SHEET_PAIRS)
    headers = list(sheet_rows[0].keys()) if sheet_rows else []
    ws.append(headers)
    for r in sheet_rows:
        ws.append([r[h] for h in headers])
    head_fill = PatternFill("solid", fgColor="DDE4EE")
    input_fill = PatternFill("solid", fgColor="FFF6D6")
    widths = {"Judul isu": 30, "Berkas SAST": 45, "Pesan SonarQube": 45, "Endpoint DAST": 45,
              "Alert ZAP": 28, "Bukti ZAP": 35, VERDICT_COL: 18, "Alasan": 50}
    for j, h in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=j)
        cell.font, cell.fill = Font(bold=True), head_fill
        cell.alignment = Alignment(wrap_text=True, vertical="top")
        ws.column_dimensions[cell.column_letter].width = widths.get(h, 14)
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "F2"
    if sheet_rows:
        v_col = ws.cell(row=1, column=headers.index(VERDICT_COL) + 1).column_letter
        a_col = ws.cell(row=1, column=headers.index("Alasan") + 1).column_letter
        last = len(sheet_rows) + 1
        dv = DataValidation(type="list", formula1='"' + ",".join(VERDICTS) + '"', allow_blank=True)
        dv.error, dv.errorTitle = "Pilih Ya, Tidak, atau Tidak pasti.", "Nilai tidak valid"
        ws.add_data_validation(dv)
        dv.add(f"{v_col}2:{v_col}{last}")
        for col in (v_col, a_col):
            for i in range(2, last + 1):
                ws[f"{col}{i}"].fill = input_fill

        summ = wb.create_sheet(SHEET_SUMMARY)
        rng = f"'{SHEET_PAIRS}'!{v_col}2:{v_col}{last}"
        summ.append(["Ukuran", "Nilai"])
        for label in VERDICTS:
            summ.append([label, f'=COUNTIF({rng},"{label}")'])
        summ.append(["Belum diisi", f'=COUNTBLANK({rng})'])
        summ.append(["Jumlah pasangan", len(sheet_rows)])
        summ.append(["Presisi = Ya / (Ya + Tidak)", '=IF((B2+B3)=0,"",B2/(B2+B3))'])
        summ["A1"].font = summ["B1"].font = Font(bold=True)
        summ.column_dimensions["A"].width = 32
        summ.column_dimensions["B"].width = 14
        summ["B7"].number_format = "0.0%"
    wb.save(path)


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    """Selang kepercayaan Wilson 95% untuk proporsi; None bila n = 0."""
    if n == 0:
        return None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return round(centre - half, 4), round(centre + half, 4)


def summarize(path: str) -> dict:
    """Menghitung presisi korelasi berbasis CWE dari lembar periksa yang sudah diisi."""
    df = pd.read_excel(path, sheet_name=SHEET_PAIRS, dtype=str).fillna("")
    df[VERDICT_COL] = df[VERDICT_COL].str.strip()
    invalid = sorted(set(df[VERDICT_COL]) - set(VERDICTS) - {""})
    if invalid:
        raise SystemExit(f"Nilai tidak dikenal pada kolom '{VERDICT_COL}': {', '.join(invalid)}")
    missing_reason = df[(df[VERDICT_COL] != "") & (df["Alasan"].str.strip() == "")]["No"].tolist()

    def stats(frame: pd.DataFrame) -> dict:
        counts = {v: int((frame[VERDICT_COL] == v).sum()) for v in VERDICTS}
        decided = counts["Ya"] + counts["Tidak"]
        return {"pairs": len(frame), **{k.lower().replace(" ", "_"): n for k, n in counts.items()},
                "not_filled": int((frame[VERDICT_COL] == "").sum()),
                "precision": round(counts["Ya"] / decided, 4) if decided else None,
                "wilson_95": wilson_interval(counts["Ya"], decided)}

    per_issue = []
    for (code, title, cwe), g in df.groupby(["Isu", "Judul isu", "CWE"], sort=False):
        per_issue.append({"issue": code, "title": title, "cwe": cwe, **stats(g)})
    return {"file": os.path.basename(path), "overall": stats(df), "per_issue": per_issue,
            "rows_without_reason": missing_reason}


def main():
    p = argparse.ArgumentParser(description="Verifikasi manual korelasi hybrid oleh peneliti.")
    sub = p.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate", help="Membuat lembar periksa Excel dari satu sesi hybrid.")
    g.add_argument("--batch-id", required=True)
    g.add_argument("--database-url", default=None, help="Default: HAST_DATABASE_URL / database/database.db")
    g.add_argument("--sonar-report", help="Laporan JSON SonarQube asli (opsional).")
    g.add_argument("--zap-report", help="Laporan JSON OWASP ZAP asli (opsional).")
    g.add_argument("--out", help="Default: tools/data/verifikasi_hybrid_<batch>.xlsx")
    s = sub.add_parser("summarize", help="Menghitung presisi dari lembar periksa yang sudah diisi.")
    s.add_argument("path")
    s.add_argument("--out", help="Simpan ringkasan sebagai JSON.")
    a = p.parse_args()

    if a.command == "generate":
        url = init_database(a.database_url)
        with session_scope(url) as session:
            rows = history_repo.list_batch(session, a.batch_id)
        if not rows:
            raise SystemExit(f"Sesi {a.batch_id} tidak ditemukan.")
        sheet_rows = build_sheet_rows(rows, sonar_index(a.sonar_report), zap_index(a.zap_report))
        if not sheet_rows:
            raise SystemExit(f"Sesi {a.batch_id} tidak memiliki pasangan hybrid.")
        out = a.out or os.path.join(ROOT_DIR, "tools", "data", f"verifikasi_hybrid_{a.batch_id}.xlsx")
        write_workbook(out, a.batch_id, sheet_rows)
        n_issues = len({r["Isu"] for r in sheet_rows})
        print(f"{len(sheet_rows)} pasangan dari {n_issues} isu ditulis ke {out}")
        return

    result = summarize(a.path)
    o = result["overall"]
    print(f"Pasangan: {o['pairs']} | Ya {o['ya']} | Tidak {o['tidak']} | Tidak pasti {o['tidak_pasti']} | "
          f"belum diisi {o['not_filled']}")
    print(f"Presisi korelasi CWE = {o['precision']} (Wilson 95%: {o['wilson_95']})")
    for it in result["per_issue"]:
        print(f"  {it['issue']} {it['cwe']:9} {it['title'][:40]:40} Ya {it['ya']}/{it['pairs']}")
    if result["rows_without_reason"]:
        print(f"Peringatan: baris tanpa alasan: {result['rows_without_reason']}")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
