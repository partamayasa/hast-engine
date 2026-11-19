# Frontend: Antarmuka Pengguna (Streamlit)

Direktori `frontend/` memuat antarmuka pengguna berbasis **Streamlit** multipage (`st.navigation`). Sejak v2, frontend adalah **klien tipis**: frontend tidak membuka basis data dan tidak memuat model ML. Setiap baca/tulis data melewati backend FastAPI melalui `utils/api_client.py`.

---

## 1. Struktur Direktori

```text
frontend/
├── app.py                       # Navigasi multipage + panel login + rute ?page=sus / ?dev=true
├── components/
│   ├── page_dashboard.py        # Dasbor (halaman pembuka): angka kunci, grafik, tenggat, tren
│   ├── page_priority.py         # Prioritas Perbaikan: kartu isu P1–P4 + form tindak lanjut
│   ├── page_decision_log.py     # Riwayat Keputusan: rekap tindak lanjut, jejak audit, ekspor Excel
│   ├── page_dss_weights.py      # Pengaturan Prioritas: aturan P1–P4, tenggat; lanjutan: bobot, metode, AHP
│   ├── page_users.py            # Pengguna: kelola akun dan peran (Administrator)
│   ├── page_dss_research.py     # (dev) Sensitivitas bobot/ER, perbandingan metode, evaluasi vs pakar
│   ├── page_sus_survey.py       # Kuesioner System Usability Scale (SUS)
│   ├── auth_panel.py            # Login/logout di sidebar, pemeriksaan hak (`can()`)
│   ├── analysis_flow.py         # Alur skoring batch (satu panggilan API) dan ringkasan metrik
│   ├── history.py               # Riwayat pemindaian, filter keparahan, grafik SHAP, ekspor CSV, hapus
│   ├── dialogs.py               # Dialog konfirmasi hapus sesi/riwayat
│   ├── tab_sast.py              # 1. SonarQube (SAST)
│   ├── tab_dast.py              # 2. OWASP ZAP (DAST)
│   ├── tab_hybrid.py            # 3. Korelasi Hybrid (pencocokan CWE Left-Base + eskalasi)
│   ├── tab_shap_visual.py       # Penjelasan Skor (SHAP), disematkan di tab SAST/DAST/Hybrid
│   ├── tab_analysis.py          # (dev) Analisis Riset RQ1 & RQ2
│   ├── tab_simulation.py        # (dev) Simulasi & Pengujian Interaktif
│   └── tab_blackbox_testing.py  # (dev) Pengujian Black-Box
├── config/                      # app_config, sonar_rules_cache (+ .sample.json)
└── utils/
    ├── api_client.py            # SATU-SATUNYA jalur data UI ke backend (timeout, ApiError, token JWT)
    ├── config.py                # Konfigurasi antarmuka, API_BASE_URL, pemeriksaan status backend
    └── formatters.py            # Pemformat label keparahan
```

---

## 2. Navigasi Halaman

| Kelompok | Halaman | Keterangan |
| :--- | :--- | :--- |
| Keputusan | **Dasbor** (pembuka) | Ringkasan isu terbuka, P1, tenggat, beban kerja, CWE teratas, sebaran keparahan, tren |
| | Prioritas Perbaikan | Daftar kerja isu: alasan, cara memperbaiki, asal skor (SHAP), lokasi, tindak lanjut, riwayat |
| | Riwayat Keputusan | Rekap keputusan lintas pemindaian, jejak audit, ekspor Excel |
| Data Pemindaian | 1. SonarQube (SAST) · 2. OWASP ZAP (DAST) · 3. Korelasi Hybrid (masing-masing memuat bagian Penjelasan Skor (SHAP)) | Unggah laporan, skoring, korelasi, riwayat sesi |
| Administrasi | Pengguna | Hanya tampil untuk peran dengan hak `users.manage` |
| Riset & QA (Dev) | Pengaturan Prioritas (aturan P1–P4, tenggat SLA, bobot dan AHP) · Analisis Riset · Sensitivitas & Evaluasi DSS · Simulasi · Pengujian Black-Box | Hanya tampil dengan `?dev=true` (atau `?test_mode=true` / `?qa=true`) |

Rute khusus `?page=sus` menampilkan kuesioner SUS tanpa navigasi.

Kontrol yang mengubah data (form tindak lanjut, hapus riwayat, pengaturan) diaktifkan atau dikunci sesuai peran pengguna yang login. Backend tetap memeriksa ulang setiap permintaan.

---

## 3. Menjalankan Frontend

1. Pastikan backend sudah berjalan di port 8000 (lihat [backend/README.md](../backend/README.md)).
2. Dari akar repositori, jalankan:
   ```bash
   uv run streamlit run frontend/app.py
   ```
3. Buka `http://localhost:8501`. Alamat jaringan (misalnya `http://192.168.x.x:8501`) ditampilkan di terminal saat startup.

Alamat backend diatur dengan variabel lingkungan `API_BASE_URL` (bawaan `http://127.0.0.1:8000`). Di Windows, gunakan `127.0.0.1`, bukan `localhost`, agar setiap permintaan tidak tertunda resolusi nama.

---

## 4. Catatan Pengembangan

- Halaman baru dibuat sebagai `components/page_*.py`, lalu didaftarkan di `pages` pada `app.py`.
- Seluruh pemanggilan API ditambahkan di `utils/api_client.py`, bukan langsung dengan `requests` di halaman.
- Teks yang tampil ke pengguna berbahasa Indonesia; identifier kode berbahasa Inggris; komentar dan docstring berbahasa Indonesia.
- Dihapus pada v2: `utils/database.py` (kini `backend/repositories/`) dan `utils/sonar_cwe_mapper.py` (kini `backend/services/parsers/`). Halaman dev Simulasi dan Black-Box masih memanggil fungsi backend di dalam proses sebagai harness QA (lihat [docs/CATATAN_PERUBAHAN_DSS.md](../docs/CATATAN_PERUBAHAN_DSS.md)).
