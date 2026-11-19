# Backend: REST API, Mesin Inferensi, dan Sistem Pendukung Keputusan (FastAPI)

Direktori `backend/` memuat layanan REST API berbasis **FastAPI** dan **Uvicorn**. Sejak v2, backend adalah **satu-satunya komponen yang membuka basis data**. Tanggung jawabnya:
- skor CVSS v4.0 (Random Forest + TF-IDF), korelasi hibrida SAST–DAST, dan penjelasan SHAP;
- parsing laporan SonarQube dan OWASP ZAP, serta riwayat pemindaian;
- autentikasi JWT dan hak akses berbasis peran (RBAC);
- DSS: pengelompokan isu, prioritas P1–P4, ranking MCDM, keputusan analis, jejak audit, dan ringkasan dasbor.

Rincian endpoint dan alur DSS tersedia di [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md). Parameter konfigurasi dijelaskan di [docs/CONFIGURATION.md](../docs/CONFIGURATION.md).

---

## 1. Struktur Direktori

```text
backend/
├── api.py               # Shim kompatibilitas: `uvicorn backend.api:app`
├── main.py              # Factory FastAPI + lifespan (migrasi DB, pemuatan model, registrasi router)
├── config.py            # Fungsi konfigurasi v1 (ER, model aktif, kelas keparahan, metadata)
├── engine.py            # Mesin inferensi RF + SHAP (tidak diubah dari v1)
├── model_loader.py      # Pemuat singleton artefak .pkl
├── core/
│   ├── settings.py      # Konfigurasi terpusat (variabel lingkungan HAST_*, jalur berkas)
│   ├── security.py      # Hash kata sandi Argon2, token JWT
│   └── roles.py         # Lima peran dan matriks hak akses
├── db/                  # models.py, session.py, bootstrap.py, migrations/ (Alembic 0001–0004)
├── repositories/        # history (riwayat pemindaian), research (+SUS), users, dss (keputusan + audit)
├── services/
│   ├── scoring.py       # Skoring batch dan korelasi pasangan SAST–DAST
│   ├── identity.py      # Kunci keputusan yang stabil antarpemindaian
│   └── parsers/         # reports.py (SonarQube, ZAP), sonar_cwe_mapper.py (aturan Sonar → CWE)
├── dss/                 # Logika keputusan murni (tanpa I/O, tanpa model ML)
│   ├── issues.py        # Pengelompokan pasangan menjadi isu (alert ZAP + CWE)
│   ├── criteria.py      # Matriks kriteria per isu
│   ├── recommender.py   # Aturan prioritas P1–P4, status, label
│   ├── mcdm.py, ahp.py  # TOPSIS, SAW, WP; AHP dengan rasio konsistensi
│   ├── explain.py       # Rantai skor, ringkasan SHAP, tanda "Perlu diperiksa"
│   ├── sensitivity.py   # Analisis sensitivitas bobot dan escalation rate
│   ├── evaluation.py    # Spearman, Kendall, Precision@k, Kendall's W, tingkat kesesuaian
│   ├── escalation.py    # Rumus eskalasi hybrid
│   ├── dashboard.py     # Ringkasan dasbor (angka kunci, beban kerja, tenggat, sebaran temuan)
│   ├── config.py        # Validasi dss_config.json
│   └── service.py       # Orkestrasi DSS (ranking, penyimpanan run, rekomendasi)
├── routers/
│   ├── deps.py          # get_db, get_current_user, require_permission
│   └── v1/              # system, scoring, findings, research, auth, dss, decisions, dashboard
└── config/              # excluded_domains, system_summary, dss_config (+ .sample.json)
```

## 2. Kelompok Endpoint

| Router | Contoh endpoint | Akses |
| :--- | :--- | :--- |
| `system` | `GET /`, `GET /api/v1/health`, `GET /sample-reports/{filename}`, `GET /system_summary.json` | Publik |
| `scoring` | `POST /predict`, `/predict/hybrid`, `/predict/shap` | Publik |
| `findings` | Unggah laporan, sesi (*batch*), riwayat, korelasi, hitung SHAP | Baca publik; hapus memerlukan `history.delete` |
| `research` | Metadata dataset, distribusi kelas, metrik model, kirim SUS (`POST /api/v1/sus`) | Publik; rekap SUS (`GET`) memerlukan `sus.read` |
| `auth` | `POST /api/v1/auth/login`, `GET /auth/me`, `GET /roles`, kelola pengguna | Kelola pengguna memerlukan `users.manage` |
| `dss` | Konfigurasi, `POST /rank`, AHP, sensitivitas, run, evaluasi | Pratinjau publik; menyimpan run memerlukan `dss.save_run`; ubah konfigurasi memerlukan `settings.manage`; evaluasi memerlukan `research.evaluate` |
| `decisions` | Daftar, `PUT /{key}`, jejak audit, ekspor Excel, kesesuaian | Baca publik; `PUT` memerlukan login dan diperiksa per kolom sesuai peran; ekspor memerlukan `report.export` |
| `dashboard` | `GET /api/v1/dashboard` | Publik (hanya baca) |

## 3. Tanggung Jawab Utama

1. **`engine.py` / `model_loader.py`**: vektorisasi TF-IDF, prediksi Random Forest, dekomposisi SHAP (`TreeExplainer`) dengan *caching*, serta mitigasi bias kosakata absen. Jalur ini sengaja tidak diubah; uji regresi emas menjaga skornya identik dengan v1.
2. **`config.py`**: ambang kelas keparahan CVSS v4.0 (NONE 0.0; LOW 0.1–3.9; MEDIUM 4.0–6.9; HIGH 7.0–8.9; CRITICAL 9.0–10.0), *escalation rate*, dan metadata aplikasi.
3. **`db/bootstrap.py`**: dipanggil saat startup. Fungsi ini:
   - menjalankan migrasi Alembic; basis data v1 diadopsi tanpa perubahan isi;
   - mengisi ulang data lama (*backfill*) dan nilai bawaan (*seed*);
   - membuat akun **Administrator** awal dari `HAST_ADMIN_USERNAME` / `HAST_ADMIN_PASSWORD` bila tabel pengguna masih kosong.
4. **`dss/`**: logika keputusan murni, diorkestrasi oleh `dss/service.py`. Keputusan analis tidak pernah ditimpa saat ranking dihitung ulang.

## 4. Menjalankan Backend

```bash
uv sync
uv run uvicorn backend.api:app --host 127.0.0.1 --port 8000          # lokal/produksi
uv run uvicorn backend.api:app --host 127.0.0.1 --port 8000 --reload # pengembangan
```

- Verifikasi: `http://127.0.0.1:8000/api/v1/health`; dokumentasi interaktif di `http://127.0.0.1:8000/docs`.
- Basis data lain (misalnya salinan untuk demo atau uji): `HAST_DATABASE_URL=sqlite:///path/ke/salinan.db`. Jangan memakai `database/database.db` riset untuk percobaan.
- Migrasi manual (opsional, karena startup sudah menjalankannya): `uv run alembic upgrade head`.
