# backend/dss/mcdm.py
"""
Metode pengambilan keputusan multikriteria (fungsi murni, tanpa I/O).

Notasi: X adalah matriks (m alternatif x n kriteria), w vektor bobot (jumlah 1),
directions[j] bernilai {"benefit", "cost"} dari sudut pandang PRIORITAS
(benefit = nilai lebih tinggi membuat alternatif lebih mendesak).

Rumus mengikuti definisi klasik (SAW; TOPSIS, Hwang & Yoon 1981; WP). Rumus ditulis secara
eksplisit (tanpa paket MCDM pihak ketiga) agar setiap langkah dapat dirujuk dan diaudit.
"""
from dataclasses import dataclass, field

import numpy as np

METHODS = ("SAW", "TOPSIS", "WP")
# Normalisasi TOPSIS. "vector" adalah bentuk klasik Hwang & Yoon (1981); "minmax" merentangkan setiap kriteria ke
# 0-1 sehingga rentang pengaruh setiap kriteria sama dengan bobotnya (bobot nominal = bobot efektif).
NORMALIZATIONS = ("minmax", "vector")
DEFAULT_NORMALIZATION = "minmax"


@dataclass
class MCDMResult:
    method: str
    scores: np.ndarray                      # nilai preferensi per alternatif (lebih tinggi = lebih mendesak)
    normalized: np.ndarray                  # r_ij
    weighted: np.ndarray                    # v_ij = w_j * r_ij (SAW/TOPSIS) atau x_ij^w_j (WP)
    extras: dict = field(default_factory=dict)


def normalize_weights(weights) -> np.ndarray:
    w = np.asarray(weights, dtype=float)
    if w.ndim != 1 or w.size == 0:
        raise ValueError("Bobot harus berupa vektor satu dimensi yang tidak kosong.")
    if np.any(~np.isfinite(w)):
        raise ValueError("Bobot mengandung nilai tidak valid (NaN/inf).")
    if np.any(w < 0):
        raise ValueError("Bobot kriteria tidak boleh negatif.")
    total = w.sum()
    if total <= 0:
        raise ValueError("Jumlah bobot harus lebih besar dari nol.")
    return w / total


def _validate(X, weights, directions) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    X = np.asarray(X, dtype=float)
    if X.ndim != 2 or X.shape[0] == 0 or X.shape[1] == 0:
        raise ValueError("Matriks keputusan harus berdimensi (alternatif x kriteria) dan tidak kosong.")
    if np.any(~np.isfinite(X)):
        raise ValueError("Matriks keputusan mengandung nilai kosong atau tidak valid.")
    w = normalize_weights(weights)
    if w.size != X.shape[1]:
        raise ValueError("Jumlah bobot tidak sama dengan jumlah kriteria.")
    d = np.asarray(directions)
    if d.size != X.shape[1] or not set(d.tolist()) <= {"benefit", "cost"}:
        raise ValueError("Arah kriteria harus 'benefit' atau 'cost' untuk setiap kriteria.")
    return X, w, d == "benefit"


def saw(X, weights, directions) -> MCDMResult:
    """
    Simple Additive Weighting.
    benefit: r = x / max(x); cost: r = min(x) / x.
    Kasus tepi: kolom benefit yang seluruhnya nol menghasilkan r = 0; kolom cost yang memuat 0 memakai
    normalisasi min-max r = (max - x) / (max - min) (r = 1 bila kolom bernilai konstan).
    """
    X, w, is_benefit = _validate(X, weights, directions)
    R = np.zeros_like(X)
    for j in range(X.shape[1]):
        col = X[:, j]
        if is_benefit[j]:
            mx = col.max()
            R[:, j] = col / mx if mx > 0 else 0.0
        elif np.all(col > 0):
            R[:, j] = col.min() / col
        else:
            mx, mn = col.max(), col.min()
            R[:, j] = (mx - col) / (mx - mn) if mx > mn else 1.0
    V = R * w
    return MCDMResult("SAW", V.sum(axis=1), R, V)


def topsis(X, weights, directions, normalization: str = "vector") -> MCDMResult:
    """
    TOPSIS: normalisasi r_ij, v = w r, solusi ideal A+ / anti-ideal A-, jarak Euclidean D+ / D-,
    kedekatan C = D- / (D+ + D-).

    Parameter:
        normalization: "vector" untuk r = x / sqrt(jumlah x^2) (klasik), atau "minmax" untuk
            r = (x - min) / (max - min). Arah benefit/cost ditangani oleh pemilihan solusi ideal, sehingga
            kedua normalisasi memakai rumus r yang sama untuk semua kriteria.

    Kasus tepi: kolom nol (vector) atau kolom konstan (minmax) menghasilkan r = 0; alternatif identik
    (D+ + D- = 0) menghasilkan C = 0,5.
    """
    X, w, is_benefit = _validate(X, weights, directions)
    if normalization == "vector":
        norms = np.sqrt((X ** 2).sum(axis=0))
        R = np.divide(X, norms, out=np.zeros_like(X), where=norms > 0)
    elif normalization == "minmax":
        lo, span = X.min(axis=0), X.max(axis=0) - X.min(axis=0)
        R = np.divide(X - lo, span, out=np.zeros_like(X), where=span > 0)
    else:
        raise ValueError(f"Normalisasi TOPSIS tidak dikenal: {normalization}. Pilihan: {', '.join(NORMALIZATIONS)}")
    V = R * w
    a_pos = np.where(is_benefit, V.max(axis=0), V.min(axis=0))
    a_neg = np.where(is_benefit, V.min(axis=0), V.max(axis=0))
    d_pos = np.sqrt(((V - a_pos) ** 2).sum(axis=1))
    d_neg = np.sqrt(((V - a_neg) ** 2).sum(axis=1))
    denom = d_pos + d_neg
    C = np.divide(d_neg, denom, out=np.full_like(d_neg, 0.5), where=denom > 0)
    return MCDMResult("TOPSIS", C, R, V, {"ideal_positive": a_pos, "ideal_negative": a_neg,
                                          "d_positive": d_pos, "d_negative": d_neg,
                                          "normalization": normalization})


def wp(X, weights, directions) -> MCDMResult:
    """
    Weighted Product: S_i = prod_j x_ij^(+-w_j) (eksponen negatif untuk cost), V_i = S_i / jumlah S.
    Kolom bernilai <= 0 digeser menjadi x' = x - min + 1 (dicatat di extras['shifted_columns']).
    """
    X, w, is_benefit = _validate(X, weights, directions)
    Xs = X.copy()
    shifted = []
    for j in range(X.shape[1]):
        if Xs[:, j].min() <= 0:
            Xs[:, j] = Xs[:, j] - Xs[:, j].min() + 1.0
            shifted.append(j)
    exps = np.where(is_benefit, w, -w)
    P = Xs ** exps
    S = P.prod(axis=1)
    return MCDMResult("WP", S / S.sum(), Xs, P, {"shifted_columns": shifted, "S": S})


def run_method(method: str, X, weights, directions, normalization: str = "vector") -> MCDMResult:
    """Menjalankan metode MCDM; `normalization` hanya berlaku untuk TOPSIS (SAW dan WP memakai normalisasinya sendiri)."""
    method = method.upper()
    if method == "SAW":
        return saw(X, weights, directions)
    if method == "TOPSIS":
        return topsis(X, weights, directions, normalization)
    if method == "WP":
        return wp(X, weights, directions)
    raise ValueError(f"Metode MCDM tidak dikenal: {method}. Pilihan: {', '.join(METHODS)}")


def rank_order(scores, tie_breakers: list[tuple] | None = None) -> list[int]:
    """
    Ranking deterministik: indeks diurutkan menurut skor (menurun). Nilai seri (|selisih| < 1e-12 setelah
    dibulatkan 10 desimal) diputus memakai tuple yang diberikan (dibandingkan menaik, sehingga berikan nilai
    negatif untuk 'lebih tinggi lebih dulu'), lalu memakai indeks asal.
    """
    scores = np.asarray(scores, dtype=float)
    n = scores.size
    tb = tie_breakers or [() for _ in range(n)]
    return sorted(range(n), key=lambda i: (-round(float(scores[i]), 10), tb[i], i))
