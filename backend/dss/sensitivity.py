# backend/dss/sensitivity.py
"""
Analisis sensitivitas ranking (fungsi murni).

Perturbasi bobot: bobot satu kriteria dikalikan (1 + delta); bobot lainnya diskalakan ulang secara
proporsional sehingga totalnya tetap 1. Setiap varian dibandingkan dengan ranking baseline
(Spearman rho, Kendall tau, perubahan anggota top-k).
"""
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


def _order(method, X, w, directions, ids, tie):
    res = run_method(method, X, w, directions)
    return [ids[i] for i in rank_order(res.scores, tie)]


def weight_sensitivity(method: str, X, weights, directions, ids: list[str], criteria_keys: list[str],
                       steps=DEFAULT_STEPS, k: int = 10, tie_breakers=None) -> dict:
    base = _order(method, X, normalize_weights(weights), directions, ids, tie_breakers)
    rows = []
    for j, key in enumerate(criteria_keys):
        for delta in steps:
            w2 = perturb_weights(weights, j, delta)
            order = _order(method, X, w2, directions, ids, tie_breakers)
            corr = rank_correlation(base, order)
            top = top_k_overlap(base, order, k)
            rows.append({
                "criterion": key, "delta": delta, "weights": w2.round(6).tolist(),
                "spearman_rho": corr["spearman_rho"], "kendall_tau": corr["kendall_tau"],
                "top_k_overlap": top["overlap"], "k": top["k"],
                "top1_changed": order[:1] != base[:1],
            })
    return {"baseline_order": base, "variants": rows}


def escalation_rate_sensitivity(build_values, method: str, weights, directions, ids: list[str],
                                rates: list[float], baseline_rate: float, k: int = 10,
                                tie_breakers=None) -> dict:
    """build_values(rate) -> X yang dihitung ulang dengan escalation rate tersebut (C1 hanya berubah untuk TP)."""
    base = _order(method, build_values(baseline_rate), weights, directions, ids, tie_breakers)
    rows = []
    for r in rates:
        order = _order(method, build_values(r), weights, directions, ids, tie_breakers)
        corr = rank_correlation(base, order)
        top = top_k_overlap(base, order, k)
        rows.append({"escalation_rate": r, "spearman_rho": corr["spearman_rho"],
                     "kendall_tau": corr["kendall_tau"], "top_k_overlap": top["overlap"], "k": top["k"],
                     "top1_changed": order[:1] != base[:1]})
    return {"baseline_rate": baseline_rate, "baseline_order": base, "variants": rows}
