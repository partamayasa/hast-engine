# backend/dss/sensitivity.py
"""
Analisis sensitivitas ranking (fungsi murni).

Perturbasi bobot: bobot satu kriteria dikalikan (1 + delta); bobot lainnya diskalakan ulang secara
proporsional sehingga totalnya tetap 1. Setiap varian dibandingkan dengan ranking baseline
(Spearman rho, Kendall tau, perubahan anggota top-k).

Bila fungsi `classify` diberikan, perbandingan memakai URUTAN AKHIR DSS, yaitu kelas prioritas lebih dulu
lalu skor MCDM di dalam kelas (sama dengan daftar kerja analis). Metrik urutan MCDM saja tetap dilaporkan
dengan awalan `mcdm_`. Tanpa `classify`, kedua urutan sama.
"""
from typing import Callable

import numpy as np

from backend.dss.evaluation import rank_correlation, top_k_overlap
from backend.dss.mcdm import normalize_weights, rank_order, run_method

DEFAULT_STEPS = (-0.30, -0.20, -0.10, 0.10, 0.20, 0.30)


def perturb_weights(weights, index: int, delta: float) -> np.ndarray:
    w = normalize_weights(weights)
    new_wi = min(max(w[index] * (1.0 + delta), 0.0), 1.0)
    rest = 1.0 - w[index]
    out = w.copy()
    if rest > 0:
        scale = (1.0 - new_wi) / rest
        out = w * scale
    out[index] = new_wi
    return normalize_weights(out)


# classify(scores) -> peringkat kelas prioritas per alternatif (1 = P1); dapat bergantung pada skor MCDM
# karena aturan boleh memakai max_rank/min_preference.
Classifier = Callable[[np.ndarray], list[int]]


def _orders(method, X, w, directions, ids, tie, classify: Classifier | None = None,
            normalization: str = "vector") -> tuple[list, list]:
    """Mengembalikan (urutan akhir, urutan MCDM). Urutan akhir = kelas prioritas, lalu urutan MCDM (stabil)."""
    res = run_method(method, X, w, directions, normalization)
    mcdm = rank_order(res.scores, tie)
    final = mcdm
    if classify is not None:
        classes = classify(res.scores)
        final = sorted(mcdm, key=lambda i: classes[i])
    return [ids[i] for i in final], [ids[i] for i in mcdm]


def _compare(base: tuple[list, list], variant: tuple[list, list], k: int) -> dict:
    out = {}
    for prefix, b, v in (("", base[0], variant[0]), ("mcdm_", base[1], variant[1])):
        corr = rank_correlation(b, v)
        top = top_k_overlap(b, v, k)
        out.update({f"{prefix}spearman_rho": corr["spearman_rho"], f"{prefix}kendall_tau": corr["kendall_tau"],
                    f"{prefix}top_k_overlap": top["overlap"], f"{prefix}top1_changed": v[:1] != b[:1]})
        out["k"] = top["k"]
    return out


def weight_sensitivity(method: str, X, weights, directions, ids: list[str], criteria_keys: list[str],
                       steps=DEFAULT_STEPS, k: int = 10, tie_breakers=None,
                       classify: Classifier | None = None, normalization: str = "vector") -> dict:
    base = _orders(method, X, normalize_weights(weights), directions, ids, tie_breakers, classify, normalization)
    rows = []
    for j, key in enumerate(criteria_keys):
        for delta in steps:
            w2 = perturb_weights(weights, j, delta)
            variant = _orders(method, X, w2, directions, ids, tie_breakers, classify, normalization)
            rows.append({"criterion": key, "delta": delta, "weights": w2.round(6).tolist(),
                         **_compare(base, variant, k)})
    return {"order_basis": "final" if classify else "mcdm", "normalization": normalization, "baseline_order": base[0],
            "baseline_mcdm_order": base[1], "variants": rows}


def escalation_rate_sensitivity(build, method: str, weights, directions, ids: list[str],
                                rates: list[float], baseline_rate: float, k: int = 10,
                                tie_breakers=None, normalization: str = "vector") -> dict:
    """
    build(rate) -> (X, classify): matriks keputusan yang dihitung ulang dengan escalation rate tersebut (C1 hanya
    berubah untuk isu yang terdeteksi kedua pemindai) beserta fungsi kelas prioritasnya (boleh None). Kelas
    ikut dihitung ulang karena perubahan skor dapat memindahkan isu ke kelas keparahan lain.
    """
    X0, classify0 = build(baseline_rate)
    base = _orders(method, X0, weights, directions, ids, tie_breakers, classify0, normalization)
    rows = []
    for r in rates:
        X, classify = build(r)
        variant = _orders(method, X, weights, directions, ids, tie_breakers, classify, normalization)
        rows.append({"escalation_rate": r, **_compare(base, variant, k)})
    return {"order_basis": "final" if classify0 else "mcdm", "normalization": normalization,
            "baseline_rate": baseline_rate,
            "baseline_order": base[0], "baseline_mcdm_order": base[1], "variants": rows}
