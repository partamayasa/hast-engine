#!/usr/bin/env python3
"""
tools/dss_followup_import/app.py

Menerapkan dampak bisnis (C6) dan upaya perbaikan (C7) yang ditetapkan penilai pada lembar Excel ke DSS melalui API.
Hanya kolom "C6 ditetapkan" dan "C7 ditetapkan" yang dibaca (lembar lama dengan "C8 ditetapkan" tetap
diterima); kolom usulan tidak pernah diterapkan. Perubahan dikirim
dengan akun penilai sendiri, sehingga jejak audit mencatat penilai yang sebenarnya.

Pemakaian:
    uv run python tools/dss_followup_import/app.py tools/data/penetapan_c6_c8_HAST-1795423044.xlsx --username analis
    uv run python tools/dss_followup_import/app.py <berkas> --username analis --apply

Tanpa --apply, alat hanya menampilkan perubahan yang akan diterapkan (uji coba). Kata sandi diminta secara interaktif,
atau dibaca dari variabel lingkungan HAST_IMPORT_PASSWORD. Alamat API diambil dari --api atau API_BASE_URL.
"""
import argparse
import getpass
import os
import sys

SHEET = "Isu"
C6_COL, C7_COL, KEY_COL, CODE_COL = "C6 ditetapkan", "C7 ditetapkan", "decision_key", "Kode isu"
# Upaya perbaikan berkode C8 sebelum penomoran kriteria dirapikan (26 November 2026).
LEGACY_COLUMNS = {"C8 ditetapkan": C7_COL}
LEVELS = range(1, 6)
DEFAULT_API = "https://research-api.partamayasa.my.id"


def _level(value, label: str, code: str) -> int | None:
    """Mengubah isian sel menjadi bilangan 1–5; sel kosong menjadi None."""
    if value is None or (isinstance(value, float) and value != value) or str(value).strip() == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{code}: {label} '{value}' bukan bilangan.")
    if number != int(number) or int(number) not in LEVELS:
        raise ValueError(f"{code}: {label} harus bilangan bulat 1–5 (ditemukan {value}).")
    return int(number)


def read_payloads(path: str) -> list[dict]:
    """
    Membaca lembar penetapan dan mengembalikan perubahan per isu.

    Mengembalikan:
        list dict {decision_key, issue_code, payload}; isu tanpa penetapan dilewati.
    """
    import pandas as pd

    df = pd.read_excel(path, sheet_name=SHEET, dtype=object)
    df = df.rename(columns={old: new for old, new in LEGACY_COLUMNS.items() if new not in df.columns})
    missing = {C6_COL, C7_COL, KEY_COL, CODE_COL} - set(df.columns)
    if missing:
        raise ValueError(f"Kolom tidak ditemukan pada sheet '{SHEET}': {', '.join(sorted(missing))}")
    out = []
    for _, row in df.iterrows():
        code = str(row[CODE_COL])
        payload = {}
        c6 = _level(row[C6_COL], "C6", code)
        c7 = _level(row[C7_COL], "C7", code)
        if c6 is not None:
            payload["asset_criticality"] = c6
        if c7 is not None:
            payload["remediation_effort"] = c7
        if payload:
            out.append({"decision_key": str(row[KEY_COL]), "issue_code": code, "payload": payload})
    return out


def main():
    p = argparse.ArgumentParser(description="Menerapkan C6 dan C7 yang ditetapkan penilai ke DSS melalui API.")
    p.add_argument("path")
    p.add_argument("--username", required=True)
    p.add_argument("--api", default=os.getenv("API_BASE_URL", DEFAULT_API))
    p.add_argument("--apply", action="store_true", help="Benar-benar menerapkan perubahan (bawaan: uji coba).")
    a = p.parse_args()

    import requests

    changes = read_payloads(a.path)
    if not changes:
        raise SystemExit("Tidak ada isu yang memiliki C6 atau C7 ditetapkan.")
    api = a.api.rstrip("/")
    password = os.getenv("HAST_IMPORT_PASSWORD") or getpass.getpass(f"Kata sandi {a.username}: ")
    r = requests.post(f"{api}/api/v1/auth/login", data={"username": a.username, "password": password}, timeout=30)
    if r.status_code != 200:
        raise SystemExit(f"Login gagal (HTTP {r.status_code}).")
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}

    current = {d["decision_key"]: d for d in requests.get(f"{api}/api/v1/decisions", timeout=30).json()["decisions"]}
    ok, failed = 0, []
    for ch in changes:
        dec = current.get(ch["decision_key"])
        if dec is None:
            failed.append((ch["issue_code"], "keputusan belum ada; simpan hasil prioritas sesi terlebih dahulu"))
            continue
        before = {k: dec.get(k) for k in ch["payload"]}
        print(f"{ch['issue_code']}: {before} -> {ch['payload']}")
        if not a.apply:
            continue
        resp = requests.put(f"{api}/api/v1/decisions/{ch['decision_key']}", json=ch["payload"], headers=headers, timeout=30)
        if resp.status_code == 200:
            ok += 1
        else:
            failed.append((ch["issue_code"], f"HTTP {resp.status_code}: {resp.text[:120]}"))
    mode = "diterapkan" if a.apply else "akan diterapkan (uji coba; jalankan dengan --apply)"
    print(f"\n{len(changes)} isu {mode}; berhasil {ok}, gagal {len(failed)}.")
    for code, why in failed:
        print(f"  {code}: {why}")
    if a.apply and ok:
        print("Simpan ulang hasil prioritas sesi (Prioritas Perbaikan) agar rekomendasi memakai nilai baru.")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
