# Visualisasi Penelitian (Random Forest, CVSS v4.0)

Modul di `tools/visualization/` merender diagram evaluasi model **Random Forest Regressor** dan statistik dataset NVD CVSS v4.0. Random Forest adalah satu-satunya model yang dipakai dalam penelitian ini. Seluruh skrip membaca artefak model (`ai-model/artifacts/`) dan data (`ai-model/data/`) yang sudah ada, tanpa melatih ulang model.

---

## 1. Berkas

| Berkas | Keluaran |
| :--- | :--- |
| `app.py` | Orkestrator CLI: jalankan satu modul, semua modul (`--all`), atau pilih lewat menu interaktif |
| `confusion_matrix.py` | Matriks konfusi 5×5 (NONE, LOW, MEDIUM, HIGH, CRITICAL) dari prediksi skor terhadap data uji |
| `shap_global_feature_importance.py` | 20 token dengan kontribusi SHAP global terbesar |
| `shap_summary_beeswarm_plot.py` | *SHAP Summary Beeswarm Plot* dengan `shap.TreeExplainer` |
| `distribution_dataset_nvd.py` | Distribusi kelas keparahan pada dataset NVD CVSS v4.0 |

---

## 2. Cara Menjalankan

Dari akar repositori:

```bash
uv run python tools/visualization/app.py --all                 # semua diagram
uv run python tools/visualization/app.py                       # menu interaktif
uv run python tools/visualization/app.py --confusion-matrix    # satu diagram
uv run python tools/visualization/app.py --feature-importance
uv run python tools/visualization/app.py --beeswarm
uv run python tools/visualization/app.py --distribution
```

Setiap skrip juga dapat dijalankan langsung, misalnya `uv run python tools/visualization/confusion_matrix.py`.

---

## 3. Lokasi Keluaran

Gambar PNG (600 dpi) disimpan ke `tools/data/` dengan awalan stempel waktu Unix, misalnya `1794896040_confusion_matrix_random_forest.png`. Pilih berkas terbaru untuk naskah. Direktori `docs/figures/` tidak lagi dipakai.
