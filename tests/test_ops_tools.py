# tests/test_ops_tools.py
"""Alat operasional: cadangan daring SQLite dengan retensi."""
import importlib.util
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("hast_backup_tool", ROOT / "tools" / "backup_db" / "app.py")
backup_tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(backup_tool)


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
