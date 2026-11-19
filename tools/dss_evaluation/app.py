#!/usr/bin/env python3
"""
tools/dss_evaluation/app.py

Evaluasi offline atas ranking DSS yang tersimpan terhadap satu atau lebih ranking pakar, untuk bab hasil
tesis. Run dibaca langsung dari basis data (sisi backend) sehingga setiap parameter ranking dapat
direproduksi dari dss_runs.

Berkas ranking pakar: CSV dengan kolom `key_id` (kode isu), diurutkan dari prioritas tertinggi ke terendah.

Pemakaian:
    uv run python tools/dss_evaluation/app.py --list-runs
    uv run python tools/dss_evaluation/app.py --run-id <uuid> --expert pakar1.csv [--expert pakar2.csv ...] --k 10
    uv run python tools/dss_evaluation/app.py --run-id <uuid> --expert pakar1.csv --out tools/data/evaluasi.json

Tidak ada angka yang dihasilkan tanpa ranking pakar yang nyata.
"""
import argparse
import json
import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import pandas as pd  # noqa: E402

from backend.db.bootstrap import init_database  # noqa: E402
from backend.db.session import session_scope  # noqa: E402
from backend.dss.evaluation import kendall_w, rank_correlation, top_k_overlap  # noqa: E402
from backend.repositories import dss as dss_repo  # noqa: E402


def read_expert(path: str) -> list[str]:
    df = pd.read_csv(path)
    if "key_id" not in df.columns:
        raise SystemExit(f"{path}: kolom 'key_id' tidak ditemukan.")
    return df["key_id"].astype(str).str.strip().tolist()


def main():
    p = argparse.ArgumentParser(description="Evaluasi ranking DSS terhadap ranking pakar.")
    p.add_argument("--database-url", default=None, help="Default: HAST_DATABASE_URL / database/database.db")
    p.add_argument("--list-runs", action="store_true")
    p.add_argument("--run-id")
    p.add_argument("--expert", action="append", default=[], help="CSV ranking pakar (boleh berulang).")
    p.add_argument("--k", type=int, default=10)
    p.add_argument("--out", help="Simpan hasil sebagai JSON.")
    a = p.parse_args()

    url = init_database(a.database_url)
    with session_scope(url) as s:
        if a.list_runs:
            for r in dss_repo.list_runs(s, limit=200):
                print(f"{r['run_id']}  {r['created_at']}  {r['batch_id']}  {r['method']}  "
                      f"bobot={r['weighting_source']}  n={r['alternatives_count']}")
            return
        if not a.run_id or not a.expert:
            p.error("--run-id dan minimal satu --expert wajib diisi (atau gunakan --list-runs).")
        run = dss_repo.get_run(s, a.run_id)
    if run is None:
        raise SystemExit("Run DSS tidak ditemukan.")

    dss_order = [it["key_id"] for it in run["items"]]
    score_order = [it["key_id"] for it in sorted(run["items"], key=lambda it: (-it["hybrid_score"], it["key_id"]))]
    experts = {os.path.basename(e): read_expert(e) for e in a.expert}

    result = {"run_id": a.run_id, "method": run["method"], "weights": run["weights"],
              "weighting_source": run["weighting_source"], "n_alternatives": len(dss_order), "k": a.k,
              "per_expert": {}}
    for name, order in experts.items():
        result["per_expert"][name] = {
            "dss_vs_expert": {**rank_correlation(dss_order, order), **top_k_overlap(dss_order, order, a.k)},
            "score_only_vs_expert": {**rank_correlation(score_order, order), **top_k_overlap(score_order, order, a.k)},
        }
    if len(experts) >= 2:
        try:
            result["inter_expert_kendall_w"] = kendall_w(list(experts.values()))
        except ValueError as e:
            result["inter_expert_kendall_w"] = {"error": str(e)}

    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)


if __name__ == "__main__":
    main()
