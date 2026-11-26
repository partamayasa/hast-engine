# frontend/utils/formatters.py

def get_severity_category(score):
    """Mengonversi skor CVSS numerik menjadi kategori keparahan kualitatif."""
    try:
        score_val = float(score)
        if score_val < 0.0 or score_val > 10.0:
            return "NONE"
        if score_val == 0.0:
            return "NONE"
        elif score_val < 4.0:
            return "LOW"
        elif score_val < 7.0:
            return "MEDIUM"
        elif score_val < 9.0:
            return "HIGH"
        else:
            return "CRITICAL"
    except (ValueError, TypeError):
        return "NONE"


def prefix_scanner(name):
    """Membersihkan nama pemindai agar dapat dipakai sebagai kunci komponen."""
    return name.replace(' ', '_').replace('(', '').replace(')', '')
