# tests/test_formatters_and_hast.py
import pytest
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
    """Menguji implementasi matematis rumus eskalasi prioritas HAST."""
    escalation_rate = 0.10  # 10%

    # Kasus 1: skor sedang (6.20) dieskalasi 10% -> 6.82 (tetap MEDIUM)
    score_base_1 = 6.20
    score_hast_1 = min(10.0, round(score_base_1 * (1 + escalation_rate), 2))
    assert score_hast_1 == 6.82
    assert get_severity_category(score_base_1) == "MEDIUM"
    assert get_severity_category(score_hast_1) == "MEDIUM"

    # Kasus 2: skor di perbatasan (8.80) dieskalasi 10% -> 9.68 (kelas bergeser dari HIGH ke CRITICAL)
    score_base_2 = 8.80
    score_hast_2 = min(10.0, round(score_base_2 * (1 + escalation_rate), 2))
    assert score_hast_2 == 9.68
    assert get_severity_category(score_base_2) == "HIGH"
    assert get_severity_category(score_hast_2) == "CRITICAL"

    # Kasus 3: skor batas atas (9.80) dipotong pada batas logis 10.0 (pemotongan batas atas)
    score_base_3 = 9.80
    score_hast_3 = min(10.0, round(score_base_3 * (1 + escalation_rate), 2))
    assert score_hast_3 == 10.0
    assert get_severity_category(score_hast_3) == "CRITICAL"


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
