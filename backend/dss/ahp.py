# backend/dss/ahp.py
"""
Pembobotan Analytic Hierarchy Process (Saaty, 1980 — verifikasi rujukan sebelum dikutip).

Bobot = eigenvektor utama ternormalisasi dari matriks perbandingan berpasangan.
Konsistensi: CI = (lambda_max - n) / (n - 1), CR = CI / RI(n); CR <= 0,10 dapat diterima.
"""
from dataclasses import dataclass

import numpy as np

# Indeks konsistensi acak (random index) Saaty
RANDOM_INDEX = {1: 0.0, 2: 0.0, 3: 0.58, 4: 0.90, 5: 1.12, 6: 1.24, 7: 1.32, 8: 1.41, 9: 1.45, 10: 1.49}
CR_THRESHOLD = 0.10


@dataclass
class AHPResult:
    weights: np.ndarray
    lambda_max: float
    ci: float
    cr: float
    ri: float

    @property
    def is_consistent(self) -> bool:
        return self.cr <= CR_THRESHOLD + 1e-12


def validate_matrix(A, tol: float = 1e-6) -> np.ndarray:
    A = np.asarray(A, dtype=float)
    if A.ndim != 2 or A.shape[0] != A.shape[1] or A.shape[0] < 1:
        raise ValueError("Matriks perbandingan berpasangan harus persegi (n x n).")
    n = A.shape[0]
    if n > max(RANDOM_INDEX):
        raise ValueError(f"AHP dibatasi maksimum {max(RANDOM_INDEX)} kriteria (tabel RI Saaty).")
    if np.any(A <= 0) or np.any(~np.isfinite(A)):
        raise ValueError("Seluruh elemen matriks AHP harus bernilai positif.")
    if not np.allclose(np.diag(A), 1.0, atol=tol):
        raise ValueError("Diagonal matriks AHP harus bernilai 1.")
    if not np.allclose(A * A.T, 1.0, atol=1e-3):
        raise ValueError("Matriks AHP harus resiprokal (a_ji = 1 / a_ij).")
    return A


def reciprocal_from_upper(upper: dict[tuple[int, int], float], n: int) -> np.ndarray:
    """Membangun matriks resiprokal lengkap dari penilaian segitiga atas {(i, j): a_ij} dengan i < j."""
    A = np.ones((n, n))
    for (i, j), v in upper.items():
        if not (0 <= i < j < n):
            raise ValueError("Indeks perbandingan harus i < j.")
        A[i, j] = float(v)
        A[j, i] = 1.0 / float(v)
    return A


def ahp_weights(A) -> AHPResult:
    A = validate_matrix(A)
    n = A.shape[0]
    if n == 1:
        return AHPResult(np.array([1.0]), 1.0, 0.0, 0.0, 0.0)
    eigvals, eigvecs = np.linalg.eig(A)
    k = int(np.argmax(eigvals.real))
    vec = np.abs(eigvecs[:, k].real)
    w = vec / vec.sum()
    lambda_max = float(eigvals[k].real)
    ci = (lambda_max - n) / (n - 1)
    ri = RANDOM_INDEX[n]
    cr = ci / ri if ri > 0 else 0.0
    return AHPResult(w, lambda_max, max(ci, 0.0), max(cr, 0.0), ri)


def aggregate_judgements(matrices: list) -> np.ndarray:
    """AHP kelompok: rata-rata geometrik per elemen dari matriks tiap pakar (sifat resiprokal tetap terjaga)."""
    if not matrices:
        raise ValueError("Minimal satu matriks pakar diperlukan.")
    stack = np.stack([validate_matrix(m) for m in matrices])
    return np.exp(np.log(stack).mean(axis=0))
