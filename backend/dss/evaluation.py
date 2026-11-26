# backend/dss/evaluation.py
"""Ukuran kesesuaian ranking untuk mengevaluasi DSS terhadap penilaian pakar (fungsi murni)."""
import math

from scipy import stats


def _clean(v):
    return None if v is None or (isinstance(v, float) and math.isnan(v)) else float(v)


def rank_correlation(order_a: list[str], order_b: list[str]) -> dict:
    """
    Spearman rho dan Kendall tau antara dua urutan atas item yang SAMA (terbaik lebih dulu).
    Item yang hanya ada di salah satu urutan diabaikan dan dilaporkan.
    """
    common = [x for x in order_a if x in set(order_b)]
    pos_b = {x: i for i, x in enumerate(order_b)}
    ranks_a = list(range(len(common)))
    ranks_b = [pos_b[x] for x in common]
    ignored = sorted(set(order_a) ^ set(order_b))
    if len(common) < 2:
        return {"n": len(common), "spearman_rho": None, "spearman_p": None,
                "kendall_tau": None, "kendall_p": None, "ignored_items": ignored}
    rho, rho_p = stats.spearmanr(ranks_a, ranks_b)
    tau, tau_p = stats.kendalltau(ranks_a, ranks_b)
    return {"n": len(common), "spearman_rho": _clean(rho), "spearman_p": _clean(rho_p),
            "kendall_tau": _clean(tau), "kendall_p": _clean(tau_p), "ignored_items": ignored}


def top_k_overlap(order_a: list[str], order_b: list[str], k: int) -> dict:
    """|top-k(A) ∩ top-k(B)| dan Precision@k dari A dengan B (pakar) sebagai rujukan."""
    k = max(1, min(int(k), len(order_a), len(order_b))) if order_a and order_b else 0
    if k == 0:
        return {"k": 0, "overlap": 0, "precision_at_k": None}
    inter = set(order_a[:k]) & set(order_b[:k])
    return {"k": k, "overlap": len(inter), "precision_at_k": len(inter) / k}


def agreement_rate(pairs: list[tuple[str | None, str | None]]) -> dict:
    """Porsi item yang sudah diputuskan dengan tindakan pilihan analis sama dengan tindakan rekomendasi."""
    decided = [(r, c) for r, c in pairs if c]
    if not decided:
        return {"decided": 0, "agreed": 0, "rate": None}
    agreed = sum(1 for r, c in decided if r == c)
    return {"decided": len(decided), "agreed": agreed, "rate": agreed / len(decided)}


def kendall_w(rankings: list[list[str]]) -> dict:
    """
    Koefisien konkordansi Kendall W untuk m ranking lengkap (tanpa nilai seri) atas n item yang sama:
    W = 12 S / (m^2 (n^3 - n)), S = jumlah (R_i - rata-rata R)^2 untuk semua item, R_i = jumlah peringkat item i.
    Juga mengembalikan aproksimasi chi-kuadrat m (n - 1) W dengan derajat kebebasan n - 1.
    """
    m = len(rankings)
    if m < 2:
        raise ValueError("Kendall's W memerlukan minimal dua ranking pakar.")
    items = set(rankings[0])
    if any(set(r) != items or len(r) != len(items) for r in rankings):
        raise ValueError("Seluruh ranking pakar harus memuat item yang sama tanpa duplikasi.")
    n = len(items)
    if n < 2:
        raise ValueError("Minimal dua item diperlukan.")
    totals = {x: 0 for x in items}
    for r in rankings:
        for pos, x in enumerate(r, start=1):
            totals[x] += pos
    mean = m * (n + 1) / 2
    s = sum((t - mean) ** 2 for t in totals.values())
    w = 12 * s / (m ** 2 * (n ** 3 - n))
    chi2 = m * (n - 1) * w
    p = float(stats.chi2.sf(chi2, n - 1))
    return {"m": m, "n": n, "W": w, "chi2": chi2, "df": n - 1, "p_value": p}
