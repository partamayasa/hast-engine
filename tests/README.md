# Pengujian Otomatis (pytest)

Direktori `tests/` memuat seluruh tes otomatis berbasis **pytest**: unit test, integration test API, skenario *black-box*, dan uji regresi emas. Tes ini menjaga dua hal:
1. fungsi aplikasi (parsing, skoring, DSS, hak akses, basis data) tetap benar;
2. **angka penelitian tidak berubah**: pipeline v2 harus menghasilkan skor yang identik dengan `v1.0.0-tesis`.

---

## 1. Struktur Direktori

```text
tests/
├── conftest.py                  # Fixture bersama: client API, DB sementara, save_rows, token per peran
├── test_ai_model.py             # Artefak model, vektorisasi TF-IDF, dan prediksi
├── test_backend_api.py          # Endpoint dasar: root, ringkasan sistem, /predict*, unduh sampel laporan
├── test_blackbox_scenarios.py   # Skenario black-box TC-SAST, DAST, HYB, ML, XAI, API, DB, EXP (kode TC sesuai naskah tesis)
├── test_database.py             # Pembuatan tabel, metadata, metrik, riwayat, adopsi DB v1 tanpa perubahan isi
├── test_formatters_and_hast.py  # Kelas keparahan CVSS v4.0 dan formula skor HAST
├── test_history_shap.py         # Rekonstruksi aditif SHAP pada riwayat
├── test_tab_shap_visual.py      # Penyiapan data visualisasi SHAP
├── test_sonar_cwe_mapper.py     # Pemetaan aturan SonarQube ke CWE
├── test_regression_golden.py    # Regresi emas: skor SAST, DAST, dan pasangan hybrid identik dengan v1
├── test_dss_core.py             # MCDM (nilai hitung tangan), AHP, aturan prioritas, eskalasi, sensitivitas, evaluasi
├── test_dss_api.py              # Endpoint DSS dan keputusan, keputusan analis tidak tertimpa, jejak audit
├── test_dss_explain.py          # Rantai skor, ringkasan SHAP, tanda "Perlu diperiksa", konteks audit
├── test_rbac.py                 # Lima peran, matriks hak, otorisasi per kolom keputusan
├── test_dashboard.py            # Ringkasan dasbor (logika murni + endpoint)
├── test_ops_tools.py            # Alat cadangan basis data
└── golden/
    └── baseline_predictions.json # Baseline emas (dibuat oleh tools/regression/generate_baseline.py)
```

---

## 2. Penanda (*markers*)

Didefinisikan di `pytest.ini`:

| Penanda | Arti |
| :--- | :--- |
| `requires_model` | Memerlukan artefak model di `ai-model/artifacts/` (tidak ada di git). Dilewati otomatis bila artefak tidak tersedia, misalnya di CI. |
| `slow` | Tes yang lama dijalankan (regresi emas). |

Setiap tes memakai basis data sementara; `database/database.db` riset tidak pernah disentuh.

---

## 3. Menjalankan Tes

Dari akar repositori:

```bash
uv run pytest                              # seluruh tes
uv run pytest -m "not slow"                # tanpa uji regresi emas
uv run pytest tests/test_dss_core.py       # satu berkas
uv run pytest -k dashboard                 # berdasarkan nama tes
```

Per November 2026, **151 tes lolos** bila artefak model tersedia.

**`test_regression_golden.py` wajib tetap lolos.** Kegagalan di sana berarti ada angka tesis yang berubah. Tes ini juga gagal bila `escalation_rate` atau domain pengecualian diubah dari nilai baseline.

Pemeriksaan tambahan sebelum menyerahkan perubahan:

```bash
uv run python -W error::SyntaxWarning -m compileall -q backend frontend ai-model tools tests
uvx pyflakes backend frontend tests
```
