# backend/dss/escalation.py
"""
Pernyataan ulang (fungsi murni) atas eskalasi hybrid yang dipakai backend.engine.run_hybrid_prediction:

    final = base + (10 - base) * ER   (hanya untuk True Positive terverifikasi), dibulatkan 2 desimal, maksimum 10.

Fungsi ini ada agar DSS dapat menghitung ulang skor hybrid untuk analisis sensitivitas escalation rate TANPA
menjalankan ulang model ML. backend/engine.py tidak diubah; tests/test_dss_core.py memastikan fungsi ini
dan engine memberi hasil yang sama. Rumus ini ditetapkan sebagai rumus kanonik (keputusan K1, 23 November 2026);
halaman riset dan simulasi di frontend memakai fungsi ini agar tidak ada rumus kedua.
"""
import numpy as np


def escalate(base_score: float, is_true_positive: bool, escalation_rate: float) -> float:
    final = float(base_score)
    if is_true_positive:
        final = final + ((10.0 - final) * float(escalation_rate))
        final = min(float(np.round(final, 2)), 10.0)
    return final
