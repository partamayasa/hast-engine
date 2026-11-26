# Dokumentasi Teknis

Direktori `docs/` memuat dokumentasi teknis aplikasi HAST: arsitektur dan konfigurasi (Sistem Pendukung Keputusan).

---

## 1. Isi Direktori

```text
docs/
├── ARCHITECTURE.md            # Arsitektur sistem, endpoint, alur DSS, model data, deployment, pengujian
└── CONFIGURATION.md           # Variabel lingkungan dan seluruh berkas konfigurasi
```

---

## 2. Ringkasan Dokumen

### `ARCHITECTURE.md`
- Prinsip arsitektur:
  - backend sebagai pemilik tunggal basis data;
  - frontend sebagai klien tipis;
  - logika DSS murni yang dapat diuji tanpa model ML.
- Struktur direktori dan daftar endpoint per router, termasuk `GET /api/v1/dashboard`.
- Alur DSS: pasangan SAST–DAST → isu → prioritas P1–P4 → urutan MCDM di dalam prioritas → keputusan analis → jejak audit.
- Halaman frontend, penerapan SHAP di DSS ("Asal skor" dan "Perlu diperiksa"), serta peran dan hak akses.
- Model data, pipeline model AI, deployment (`app.sh`, tmux), dan strategi pengujian.

### `CONFIGURATION.md`
| Berkas | Isi |
| :--- | :--- |
| `.env` (templat `.env.sample`) | Rahasia JWT, akun Administrator awal, URL basis data, batas unggah, SonarQube API, URL backend untuk frontend |
| `backend/config/dss_config.json` | Metode MCDM dan sumber bobot, kriteria, skala kekritisan aset dan upaya, aturan prioritas P1–P4, tenggat SLA, ambang "Perlu diperiksa", matriks AHP |
| `ai-model/config/ai_config.json` | Model aktif, *escalation rate*, parameter TF-IDF dan Random Forest |
| `backend/config/excluded_domains.json` | Domain di luar cakupan pemindaian DAST |
| `backend/config/system_summary.json` | Ringkasan sistem hasil pipeline model |
| `frontend/config/app_config.json` | Judul, deskripsi, dan versi antarmuka |
| `frontend/config/sonar_rules_cache.json` | Tembolok pemetaan aturan SonarQube → CWE |

Berkas runtime (`*.json` non-sample dan `.env`) tidak di-commit; salin dari berkas `*.sample.json` / `.env.sample`.

---

## 3. Gambar Penelitian

Diagram evaluasi model (matriks konfusi, *feature importance* SHAP, *beeswarm plot*, distribusi dataset) **tidak** disimpan di `docs/`. Diagram dibuat ulang dengan modul visualisasi dan disimpan ke `tools/data/`:

```bash
uv run python tools/visualization/app.py --all
```

Lihat [tools/visualization/README.md](../tools/visualization/README.md).
