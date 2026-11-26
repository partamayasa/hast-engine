# tests/test_formatters_and_hast.py
import pytest
from backend.dss.escalation import escalate
from frontend.utils.formatters import get_severity_category


def test_severity_category_mapping():
    """Menguji konsistensi pemetaan skor numerik CVSS v4.0 ke kategori keparahan berupa teks."""
    # Skor 0.0 -> NONE
    assert get_severity_category(0.0) == "NONE"
    assert get_severity_category(0) == "NONE"

    # Rentang 0.1 - 3.9 -> LOW
    assert get_severity_category(0.1) == "LOW"
    assert get_severity_category(2.0) == "LOW"
    assert get_severity_category(3.9) == "LOW"

    # Rentang 4.0 - 6.9 -> MEDIUM
    assert get_severity_category(4.0) == "MEDIUM"
    assert get_severity_category(5.5) == "MEDIUM"
    assert get_severity_category(6.9) == "MEDIUM"

    # Rentang 7.0 - 8.9 -> HIGH
    assert get_severity_category(7.0) == "HIGH"
    assert get_severity_category(8.0) == "HIGH"
    assert get_severity_category(8.9) == "HIGH"

    # Rentang 9.0 - 10.0 -> CRITICAL
    assert get_severity_category(9.0) == "CRITICAL"
    assert get_severity_category(9.8) == "CRITICAL"
    assert get_severity_category(10.0) == "CRITICAL"


def test_hast_escalation_formula():
    """Menguji rumus eskalasi kanonik HAST (keputusan K1): hybrid = base + (10 - base) x ER."""
    escalation_rate = 0.10  # 10% dari sisa jarak menuju 10,0

    # Kasus 1: skor sedang (6.20) naik 10% dari sisa jarak (3.80) -> 6.58 (tetap MEDIUM)
    assert escalate(6.20, True, escalation_rate) == 6.58
    assert get_severity_category(6.20) == "MEDIUM"
    assert get_severity_category(6.58) == "MEDIUM"

    # Kasus 2: skor di dekat batas (6.80) -> 7.12 (kelas bergeser dari MEDIUM ke HIGH)
    assert escalate(6.80, True, escalation_rate) == 7.12
    assert get_severity_category(6.80) == "MEDIUM"
    assert get_severity_category(7.12) == "HIGH"

    # Kasus 3: skor tinggi tidak pernah melampaui 10,0 dan urutannya tetap terjaga (tanpa pemotongan/seri)
    assert escalate(9.80, True, escalation_rate) == 9.82
    assert escalate(9.50, True, escalation_rate) == 9.55
    assert escalate(9.50, True, escalation_rate) < escalate(9.80, True, escalation_rate) <= 10.0

    # Kasus 4: temuan yang tidak terverifikasi tidak dieskalasi
    assert escalate(6.20, False, escalation_rate) == 6.20


def test_false_positive_reduction_math():
    """Menguji validasi teorema probabilitas independen untuk reduksi False Positive HAST."""
    p_fp_sast = 0.35  # Rata-rata FP SAST 35%
    p_fp_dast = 0.20  # Rata-rata FP DAST 20%

    # Probabilitas FP ortogonal yang terjadi bersamaan pada CWE yang sama
    p_fp_hast = p_fp_sast * p_fp_dast
    assert round(p_fp_hast, 4) == 0.0700

    # Efisiensi reduksi dibanding FP SAST tunggal
    reduction_efficiency = (1 - (p_fp_hast / p_fp_sast)) * 100
    assert round(reduction_efficiency, 1) == 80.0
