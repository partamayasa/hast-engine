#!/usr/bin/env python3
"""
tools/backup_db/app.py

Cadangan daring yang konsisten untuk basis data riset SQLite (API backup sqlite3, aman dijalankan saat API
berjalan dalam mode WAL) dengan retensi sederhana.

Pemakaian:
    python tools/backup_db/app.py                 # cadangkan database/database.db -> database/backups/
    python tools/backup_db/app.py --keep 14       # simpan 14 cadangan otomatis terbaru
    python tools/backup_db/app.py --db path/to.db --out path/to/dir

Jadwalkan dengan cron / Task Scheduler, mis. harian:  0 2 * * *  cd /srv/hast && python3 tools/backup_db/app.py --keep 14
Hanya memakai pustaka standar sehingga juga dapat dijalankan di host di luar virtualenv / kontainer.
"""
import argparse
import datetime
import hashlib
import sqlite3
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
PREFIX = "database-auto-"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def backup(db: Path, out_dir: Path) -> Path:
    if not db.exists():
        raise SystemExit(f"Basis data tidak ditemukan: {db}")
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{PREFIX}{datetime.datetime.now():%Y%m%d-%H%M%S}.db"
    src = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    dst = sqlite3.connect(target)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    check = sqlite3.connect(target)
    try:
        if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise SystemExit(f"Pemeriksaan integritas cadangan gagal: {target}")
    finally:
        check.close()
    return target


def prune(out_dir: Path, keep: int) -> list[Path]:
    files = sorted(out_dir.glob(f"{PREFIX}*.db"), reverse=True)
    removed = files[keep:] if keep > 0 else []
    for f in removed:
        f.unlink()
    return removed


def main():
    p = argparse.ArgumentParser(description="Cadangan daring basis data SQLite HAST DSS.")
    p.add_argument("--db", type=Path, default=ROOT_DIR / "database" / "database.db")
    p.add_argument("--out", type=Path, default=ROOT_DIR / "database" / "backups")
    p.add_argument("--keep", type=int, default=0, help="Simpan N cadangan otomatis terbaru (0 = tanpa penghapusan).")
    args = p.parse_args()
    target = backup(args.db, args.out)
    print(f"Cadangan dibuat: {target}  sha256={sha256(target)}")
    for f in prune(args.out, args.keep):
        print(f"Cadangan lama dihapus: {f.name}")


if __name__ == "__main__":
    main()
