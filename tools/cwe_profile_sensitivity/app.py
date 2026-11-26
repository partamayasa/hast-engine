#!/usr/bin/env python3
"""
tools/cwe_profile_sensitivity/app.py

Menguji apakah urutan DSS berubah bila tabel acuan profil CWE (kriteria C3 dan C4) dibangun dengan aturan pemilihan
kode CWE yang berbeda. dataset_collector.py menyimpan satu kode per entri NVD, yaitu kode pertama pada blok kelemahan
terakhir, padahal banyak entri memuat lebih dari satu kode. Alat ini membandingkan tiga aturan:
- last  : kode pertama pada blok kelemahan terakhir (aturan sistem, sebagai pemeriksaan);
- first : kode yang pertama tercantum pada entri;
- all   : seluruh kode; satu entri dihitung pada setiap kodenya.

Basis data sumber hanya dibaca: alat bekerja pada salinan sementara yang dihapus setelah selesai, dan run tidak
disimpan. Tabel acuan yang dipakai sistem tidak diubah.

Pemakaian (memerlukan ai-model/data/nvdcve/*.json, cve_cvss4_dataset.csv, dan cwe_cvss4_lookup_table.csv):
    uv run python tools/cwe_profile_sensitivity/app.py --batch-id HAST-1795423044
    uv run python tools/cwe_profile_sensitivity/app.py --batch-id HAST-1795423044 --db salinan.db --out tools/data/uji_profil_cwe.json
"""
import argparse
import json
import os
import sqlite3
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import pandas as pd  # noqa: E402

from backend.core.settings import get_settings  # noqa: E402
from backend.db.session import dispose_engine, session_scope, sqlite_url_for  # noqa: E402
from backend.dss import service  # noqa: E402
from backend.dss.evaluation import rank_correlation, top_k_overlap  # noqa: E402
from backend.repositories import dss as dss_repo  # noqa: E402

DATA_DIR = Path(ROOT_DIR) / "ai-model" / "data"
RULES = ("last", "first", "all")
TOP_K = (3, 5, 10)
# Kolom yang tidak diagregasi; sama dengan ai-model/preprocessing/cwe_profiler.py.
EXCLUDED_COLS = {"cwe_code", "cve_id", "mod_date", "pub_date", "cvss_severity", "summary"}


def english_codes(weaknesses: list[dict]) -> list[list[str]]:
    """Mengembalikan kode CWE berbahasa Inggris per blok kelemahan (blok tanpa kode dilewati)."""
    blocks = [[d["value"] for d in w.get("description", []) if d.get("lang") == "en"] for w in weaknesses]
    return [b for b in blocks if b]


def codes_by_rule(weaknesses: list[dict], rule: str) -> list[str]:
    """
    Memilih kode CWE suatu entri NVD menurut aturan.

    Parameter:
        weaknesses: daftar `weaknesses` pada entri CVE (format NVD JSON 2.0).
        rule: "last", "first", atau "all".

    Mengembalikan:
        list kode CWE; kosong bila entri tidak memiliki kode.
    """
    blocks = english_codes(weaknesses)
    if not blocks:
        return []
    if rule == "last":
        return [blocks[-1][0]]
    if rule == "first":
        return [blocks[0][0]]
    if rule == "all":
        return list(dict.fromkeys(code for block in blocks for code in block))
    raise ValueError(f"Aturan tidak dikenal: {rule}")


def load_weaknesses(feed_dir: Path) -> dict[str, list[dict]]:
    """Membaca `weaknesses` setiap CVE yang memiliki penilaian CVSS v4.0 dari seluruh berkas feed."""
    files = sorted(feed_dir.glob("nvdcve-2.0-*.json"))
    if not files:
        raise FileNotFoundError(f"Berkas feed NVD tidak ditemukan di {feed_dir}.")
    out = {}
    for path in files:
        with open(path, encoding="utf-8") as f:
            for item in json.load(f).get("vulnerabilities", []):
                cve = item.get("cve", {})
                if cve.get("metrics", {}).get("cvssMetricV40"):
                    out[cve.get("id")] = cve.get("weaknesses", [])
    return out


def _mode(values: pd.Series):
    return values.mode().iloc[0] if not values.mode().empty else "NONE"


def build_profile(dataset: pd.DataFrame, weaknesses: dict[str, list[dict]], rule: str) -> pd.DataFrame:
    """Membangun profil CWE dengan agregasi yang sama seperti cwe_profiler.py, tetapi dengan aturan kode tertentu."""
    frame = dataset.assign(cwe_code=dataset["cve_id"].map(lambda c: codes_by_rule(weaknesses.get(c, []), rule)))
    frame = frame.explode("cwe_code").dropna(subset=["cwe_code"])
    cols = [c for c in frame.columns if c not in EXCLUDED_COLS]
    return frame.groupby("cwe_code").agg({c: "mean" if c == "cvss_score" else _mode for c in cols}).reset_index()


@contextmanager
def database_copy(source: Path):
    """Salinan daring basis data di folder sementara; sumber hanya dibuka untuk dibaca."""
    if not source.exists():
        raise FileNotFoundError(f"Basis data tidak ditemukan: {source}")
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "salinan.db"
        src = sqlite3.connect(f"{source.resolve().as_uri()}?mode=ro", uri=True)
        dst = sqlite3.connect(target)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        url = sqlite_url_for(target)
        try:
            yield url
        finally:
            dispose_engine(url)


@contextmanager
def lookup_override(path: Path):
    """Mengganti sementara tabel acuan profil CWE yang dibaca mesin DSS."""
    original = service.crit.load_cwe_lookup
    service.crit.load_cwe_lookup = lambda _path: original(path)
    try:
        yield
    finally:
        service.crit.load_cwe_lookup = original


def rank_with(url: str, batch_id: str, lookup_path: Path) -> dict:
    """Mengurutkan sesi dengan tabel acuan tertentu tanpa menyimpan run."""
    with lookup_override(lookup_path), session_scope(url) as s:
        return service.rank_batch(s, batch_id, persist=False)


def latest_run(url: str, batch_id: str) -> dict | None:
    """Run terakhir yang tersimpan untuk sesi, sebagai acuan bahwa salinan menghasilkan urutan yang sama."""
    with session_scope(url) as s:
        runs = dss_repo.list_runs(s, batch_id, limit=1)
        return dss_repo.get_run(s, runs[0]["run_id"]) if runs else None


def final_order(run: dict) -> list[str]:
    return [i["decision_key"] for i in run["items"]]


def mcdm_order(run: dict) -> list[str]:
    return [i["decision_key"] for i in sorted(run["items"], key=lambda i: i["mcdm_rank"])]


def single_score_order(run: dict) -> list[str]:
    return [i["decision_key"] for i in sorted(run["items"], key=lambda i: (-i["hybrid_score"], i["issue_code"]))]


def agreement(a: list[str], b: list[str]) -> dict:
    corr = rank_correlation(a, b)
    return {"spearman_rho": round(corr["spearman_rho"], 3), "kendall_tau": round(corr["kendall_tau"], 3),
            **{f"top_{k}_overlap": top_k_overlap(a, b, k)["overlap"] for k in TOP_K}}


def same_result(a: dict, b: dict) -> bool:
    def key(run):
        return [(i["decision_key"], i["hybrid_score"], i["priority"], i["preference"]) for i in run["items"]]
    return key(a) == key(b)


def compare(base: dict, variant: dict) -> dict:
    """
    Membandingkan hasil pengurutan varian dengan urutan dasar.

    Mengembalikan:
        dict korelasi urutan akhir dan TOPSIS, korelasi terhadap skor tunggal, jumlah isu yang berpindah peringkat
        atau kelas, pergeseran terjauh, dan banyaknya peringkat teratas yang identik.
    """
    a, b = final_order(base), final_order(variant)
    pos_a, pos_b = {k: n for n, k in enumerate(a, 1)}, {k: n for n, k in enumerate(b, 1)}
    info = {i["decision_key"]: i for i in base["items"]}
    priority = {i["decision_key"]: i["priority"] for i in variant["items"]}
    moved = sorted(((abs(pos_a[k] - pos_b[k]), k) for k in a if pos_a[k] != pos_b[k]), reverse=True)
    values = [{i["decision_key"]: {c["code"]: c["value"] for c in i["criteria"]} for i in r["items"]}
              for r in (base, variant)]
    return {
        "final": agreement(a, b), "mcdm": agreement(mcdm_order(base), mcdm_order(variant)),
        "vs_single_score": agreement(b, single_score_order(variant)),
        "identical_top": next((n for n, (x, y) in enumerate(zip(a, b)) if x != y), len(a)),
        "moved_issues": len(moved), "max_shift": moved[0][0] if moved else 0,
        "moved_classes": sorted({info[k]["priority"] for _, k in moved}),
        "priority_changed": sum(info[k]["priority"] != priority[k] for k in a),
        "criteria_changed": {c: sum(abs(values[0][k][c] - values[1][k][c]) > 1e-9 for k in a) for c in ("C3", "C4")},
        "largest_shifts": [{"title": info[k]["title"], "cwe_id": info[k]["cwe_id"], "from": pos_a[k], "to": pos_b[k]}
                           for _, k in moved[:5]],
    }


def analyse(batch_id: str, db: Path, data_dir: Path = DATA_DIR) -> dict:
    """Menjalankan seluruh perbandingan pada salinan basis data dan mengembalikan ringkasannya."""
    dataset = pd.read_csv(data_dir / "cve_cvss4_dataset.csv")
    weaknesses = load_weaknesses(data_dir / "nvdcve")
    codes = {c: {r: codes_by_rule(weaknesses.get(c, []), r) for r in RULES} for c in dataset["cve_id"]}
    result = {
        "batch_id": batch_id, "entries": len(dataset),
        "entries_with_multiple_codes": sum(len(v["all"]) > 1 for v in codes.values()),
        "entries_first_differs_from_last": sum(v["first"] != v["last"] for v in codes.values()), "variants": {},
    }
    with database_copy(db) as url, tempfile.TemporaryDirectory() as tmp:
        base = rank_with(url, batch_id, get_settings().cwe_lookup_path)
        stored = latest_run(url, batch_id)
        result["issues"] = len(base["items"])
        result["baseline_matches_stored_run"] = same_result(base, stored) if stored else None
        result["baseline_vs_single_score"] = agreement(final_order(base), single_score_order(base))
        for rule in RULES:
            path = Path(tmp) / f"lookup_{rule}.csv"
            profile = build_profile(dataset, weaknesses, rule)
            profile.to_csv(path, index=False)
            result["variants"][rule] = {"profile_rows": len(profile),
                                        **compare(base, rank_with(url, batch_id, path))}
    return result


def print_report(r: dict) -> None:
    print(f"Sesi {r['batch_id']}: {r['issues']} isu")
    print(f"Entri dataset {r['entries']}; lebih dari satu kode CWE {r['entries_with_multiple_codes']}; "
          f"kode pertama berbeda dari kode tersimpan {r['entries_first_differs_from_last']}")
    print(f"Urutan dasar sama dengan run tersimpan: {r['baseline_matches_stored_run']}")
    if not r["variants"]["last"]["moved_issues"] == 0:
        print("PERINGATAN: aturan 'last' tidak mereproduksi tabel acuan sistem; periksa versi dataset dan feed.")
    for rule, v in r["variants"].items():
        f, m, s = v["final"], v["mcdm"], v["vs_single_score"]
        print(f"\n[{rule}] {v['profile_rows']} baris profil; C3 berubah pada {v['criteria_changed']['C3']} isu, "
              f"C4 pada {v['criteria_changed']['C4']} isu")
        print(f"  urutan akhir : rho {f['spearman_rho']:.3f}  tau {f['kendall_tau']:.3f}  top-10 {f['top_10_overlap']}")
        print(f"  TOPSIS saja  : rho {m['spearman_rho']:.3f}  tau {m['kendall_tau']:.3f}")
        print(f"  vs skor tunggal: rho {s['spearman_rho']:.3f}  tau {s['kendall_tau']:.3f}")
        print(f"  peringkat teratas identik {v['identical_top']}; isu berpindah {v['moved_issues']} "
              f"(kelas {', '.join(v['moved_classes']) or '-'}), terjauh {v['max_shift']}; "
              f"kelas prioritas berubah {v['priority_changed']}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Uji pengaruh aturan pemilihan kode CWE terhadap urutan DSS.")
    ap.add_argument("--batch-id", required=True, help="ID sesi hybrid, misalnya HAST-1795423044")
    ap.add_argument("--db", type=Path, default=Path(ROOT_DIR) / "database" / "database.db",
                    help="basis data sumber (hanya dibaca)")
    ap.add_argument("--out", type=Path, help="simpan ringkasan JSON")
    a = ap.parse_args()
    try:
        result = analyse(a.batch_id, a.db)
    except (FileNotFoundError, LookupError, ValueError) as e:
        print(f"Gagal: {e}", file=sys.stderr)
        return 1
    print_report(result)
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nRingkasan disimpan: {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
