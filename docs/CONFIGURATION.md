# Dokumentasi Konfigurasi Sistem HAST (`CONFIGURATION.md`)

Dokumen ini memuat panduan teknis, variasi parameter, serta dampak operasional dari berkas konfigurasi utama (`ai_config.json`, `excluded_domains.json`, `app_config.json`, `sonar_rules_cache.json`, `system_summary.json`, dan sejak v2 `dss_config.json`) serta variabel lingkungan (`.env`) yang digunakan oleh Dasbor Frontend Streamlit, Mesin Model Prediksi, dan Backend API.

Setiap berkas runtime `*.json` di-ignore git; versi `*.sample.json` adalah templat terkontrol versi yang dipakai sebagai cadangan bila berkas runtime belum ada. Seluruh jalur berkas dibaca dari satu sumber, yaitu `backend/core/settings.py`, sehingga dapat dialihkan dengan variabel lingkungan berprefiks `HAST_`.

---

## Variabel Lingkungan (`.env`)

### Jalur Berkas: `.env` (runtime, di-ignore git) & `.env.sample` (templat)

| Variabel | Bawaan | Catatan |
| :--- | :--- | :--- |
| `HAST_ENVIRONMENT` | `development` | `production` memunculkan peringatan bila `HAST_JWT_SECRET` tidak diatur. |
| `HAST_JWT_SECRET` | acak per proses | **Wajib di produksi.** Tanpa nilai tetap, token login hangus setiap kali server dimulai ulang. |
| `HAST_JWT_EXPIRE_MINUTES` | `480` | Masa berlaku token login (menit). |
| `HAST_ADMIN_USERNAME`, `HAST_ADMIN_PASSWORD` | kosong | Akun Administrator pertama; dibuat hanya bila tabel `users` masih kosong. |
| `HAST_DATABASE_URL` | `sqlite:///<repo>/database/database.db` | URL SQLAlchemy. Lihat catatan PostgreSQL di bawah. |
| `HAST_MAX_UPLOAD_MB` | `50` | Batas ukuran unggahan laporan pada backend. |
| `HAST_RF_MODEL_PATH`, `HAST_TFIDF_PATH`, `HAST_CWE_LOOKUP_PATH`, `HAST_DSS_CONFIG_PATH`, … | jalur repositori | Seluruh atribut `Settings` dapat dialihkan dengan prefiks `HAST_`. |
| `SONAR_HOST_URL`, `SONAR_TOKEN` | `http://localhost:9000`, kosong | Dipakai oleh `tools/convert_sonar_to_cwe`. |
| `API_BASE_URL` | `http://127.0.0.1:8000` | Alamat backend dari sisi frontend. |
| `PUBLIC_API_BASE_URL` | = `API_BASE_URL` | Alamat backend yang dapat dijangkau browser (tautan unduhan laporan sampel). Bila kosong, memakai `API_BASE_URL`. Di balik Nginx Proxy Manager isi `https://<domain>`, karena `/api` dan `/sample-reports` diteruskan ke `hast-api:8000`. |
| `PROXY_NETWORK` | `proxy` | Nama jaringan Docker eksternal yang juga tersambung ke container Nginx Proxy Manager (`docker-compose.yml`). |

**Catatan PostgreSQL:** model ORM dan migrasi Alembic bersifat netral terhadap basis data. Langkah *seed* dan *backfill* data lama di `backend/db/bootstrap.py` di-port apa adanya dari v1 dan masih memakai sintaks SQLite (`INSERT OR REPLACE`, `datetime('now')`). SQLite (mode WAL) adalah konfigurasi yang diuji.

---

## Konfigurasi Sistem Pendukung Keputusan (`dss_config.json`)

### Jalur Berkas: `backend/config/dss_config.json` (runtime) & `backend/config/dss_config.sample.json` (templat)

Berkas runtime dibuat otomatis ketika manajer menyimpan konfigurasi atau bobot AHP melalui halaman **Bobot Kriteria**. Isinya divalidasi setiap kali dimuat dan disimpan.

```json
{
  "method": "TOPSIS",

  /* Pilihan: ['TOPSIS', 'SAW', 'WP'] | Catatan: Metode MCDM bawaan. Dapat diganti sementara pada panel what-if. */

  "weighting_source": "config",

  /* Pilihan: ['config', 'ahp', 'manual', 'entropy'] | Catatan: Asal bobot. Otomatis menjadi 'ahp' saat bobot AHP disimpan dan 'manual' saat bobot diubah tangan. Dicatat pada setiap run (dss_runs). */

  "criteria": [
    {"code": "C1", "key": "hybrid_score", "label": "Skor keparahan hybrid (CVSS 4.0 prediksi)", "direction": "benefit", "weight": 0.30, "enabled": true}
  ],

  /* Kunci yang didukung: hybrid_score, true_positive, exploitability, impact, prevalence, asset_criticality, remediation_effort.
     'direction' dilihat dari sudut prioritas: benefit = nilai lebih tinggi berarti lebih mendesak; cost = sebaliknya.
     Bobot kriteria aktif dinormalisasi otomatis (jumlah = 1). BOBOT DI TEMPLAT ADALAH NILAI CONTOH, BUKAN HASIL PENELITIAN. */

  "asset_criticality": {"default": 3, "rules": [{"pattern": "(?i)(auth|login|payment)", "value": 5}]},

  /* Catatan: Nilai kriteria C6 bila analis belum mengisinya. 'pattern' (regex) dicocokkan dengan "<komponen SAST> | <komponen DAST>"; aturan pertama yang cocok dipakai. */

  "remediation_effort": {"default": 2},

  /* Catatan: Nilai kriteria C8 (1-3) bila analis belum mengisinya. */

  "recommendation_rules": [
    {"id": "R1", "when": {"severity_in": ["CRITICAL"], "true_positive": true}, "action": "REMEDIATE_NOW"},
    {"id": "R9", "when": {}, "action": "REVIEW_OR_ACCEPT"}
  ],

  /* Catatan: Dievaluasi berurutan; aturan pertama yang cocok menang dan ID-nya ditampilkan pada penjelasan.
     Kondisi: severity_in, true_positive, min_hybrid_score, max_rank, min_preference.
     Aksi: REMEDIATE_NOW, REMEDIATE_SCHEDULED, PLAN, REVIEW_OR_ACCEPT, ACCEPT_RISK, FALSE_POSITIVE, DEFER.
     Aturan terakhir wajib berupa penampung ("when": {}). */

  "sla_days": {"REMEDIATE_NOW": null, "REMEDIATE_SCHEDULED": null, "PLAN": null, "REVIEW_OR_ACCEPT": null},

  /* Pilihan: bilangan bulat >= 0 atau null | Catatan: Tenggat (hari) sejak rekomendasi. Ini KEBIJAKAN ORGANISASI, bukan standar industri; null = tanpa tenggat. */

  "ahp": {"criteria": [], "matrix": null, "consistency_ratio": null, "source": null}

  /* Catatan: Diisi otomatis saat bobot AHP disimpan (hanya bila CR <= 0,10), termasuk sumber penilaian pakar. */
}
```

---

## Konfigurasi Eksperimen Kerentanan dan Korelasi Hibrida (`ai_config.json`)

### Jalur Berkas: `ai-model/config/ai_config.json`

```json
{
  "active_model": "Random Forest",

  /* Pilihan: ['Random Forest'] (Bawaan: 'Random Forest') | Catatan: Algoritma mesin model terlatih untuk memproses teks kerentanan. Tersinkronisasi secara datar dengan perutean backend. */

  "escalation_rate": 0.15,

  /* Pilihan: Bilangan desimal antara 0.00 dan 1.00 (Bawaan: 0.15) | Catatan: Pengali nilai risiko kerentanan yang diterapkan pada Tab 3 ketika suatu kerentanan terkonfirmasi aktif (True Positive) melalui pencocokan kode CWE. Digunakan langsung sebagai faktor pengali skor.
     CATATAN v2: implementasi backend/engine.py menerapkan final = base + (10 - base) x ER untuk pasangan True Positive, sedangkan tests/test_formatters_and_hast.py memakai base x (1 + ER). Lihat Keputusan Terbuka K1 di docs/CATATAN_PERUBAHAN_DSS.md. */

  "preprocessing": {
    "comparison_scheme": "k-fold",
    /* Pilihan: ['split', 'k-fold'] (Bawaan: 'k-fold') | Catatan: Menentukan skema evaluasi untuk validasi model. 'split' menerapkan partisi standar 80:20 data latih-uji (cepat). 'k-fold' menerapkan 5-fold cross-validation. */

    "max_features": 5000
    /* Pilihan: Bilangan bulat positif (Bawaan: 5000) | Catatan: Membatasi ukuran kosakata maksimum (jumlah fitur) yang diekstraksi oleh TF-IDF Vectorizer. Nilai yang lebih rendah (misalnya 1000 atau 2500) memangkas dimensi, menghasilkan ukuran model lebih ringkas dan eksekusi lebih cepat. */
  },
  "model_hyperparameters": {
    "random_forest": {
      "criterion": "squared_error",
      /* Pilihan: ['squared_error', 'absolute_error'] (Bawaan: 'squared_error') | Catatan: Metrik kualitas pembagian cabang pohon keputusan. 'squared_error' berbasis MSE (komputasi cepat). 'absolute_error' (MAE) lebih tangguh terhadap gangguan teks ekstrem tetapi memperlambat proses komputasi secara signifikan. */
      
      "n_estimators": 100,
      /* Pilihan: Bilangan bulat positif (Bawaan: 100) | Catatan: Jumlah pohon keputusan independen yang dibangun secara paralel untuk agregasi suara ensambel. Jumlah pohon yang lebih banyak mereduksi varians prediksi dan menstabilkan kinerja pelatihan. */

      "max_depth": 25
      /* Pilihan: Bilangan bulat positif atau null (Bawaan: 25) | Catatan: Membatasi kedalaman maksimum setiap pohon keputusan. Pembatasan kedalaman (misalnya 12, 15, atau 25) mempercepat waktu pelatihan model dan komputasi nilai SHAP secara eksponensial. Berikan nilai null untuk kedalaman tanpa batas. */
    }
  }
}
```

---

## Konfigurasi Pengecualian Cakupan Domain Dinamis (`excluded_domains.json`)

### Jalur Berkas: `backend/config/excluded_domains.json`

```json
{
  "unprocessing_domains": [
    "facebook.com",
    "google.com",
    "google-analytics.com",
    "googleapis.com",
    "gstatic.com",
    "mozilla.com",
    "mozilla.net",
    "mozilla.org"
  ]

  /* Pilihan: Larik string yang memuat nama domain/FQDN | Catatan: Konfigurasi penyaringan waktu-nyata. Berfungsi mencegah pemborosan sumber daya komputasi backend dan kalkulasi grafik SHAP untuk derau eksternal yang tidak sah atau di luar cakupan pengujian. */
}
```

---

## Konfigurasi Aplikasi Dasbor Frontend (`app_config.json`)

### Jalur Berkas: `frontend/config/app_config.json`

```json
{
  "api_title": "Model Penilaian Kerentanan HAST Terintegrasi",

  /* Pilihan: String kustom | Catatan: Menentukan judul utama yang ditampilkan pada bagian atas dasbor antarmuka Streamlit. */

  "api_description": "Model Intelligent Vulnerability Management: Integrasi Pemindaian SAST & DAST",

  /* Pilihan: String kustom | Catatan: Teks subjudul tersinkronisasi yang ditampilkan tepat di bawah judul utama halaman. */

  "app_version": "1.0.0",

  /* Pilihan: Format semantic versioning (misal '1.0.0') | Catatan: Penomoran rilis versi eksplisit yang dicantumkan pada metadata catatan kaki untuk kebutuhan jejak audit. */

  "active_model": "Random Forest"

  /* Pilihan: ['Random Forest'] (Bawaan: 'Random Forest') | Catatan: Algoritma model cadangan frontend yang digunakan saat status server Backend API sedang tidak aktif. */
}
```

---

## Konfigurasi Pemetaan CWE dan Tembolok Aturan SonarQube (`sonar_rules_cache.json`)

### Jalur Berkas: `frontend/config/sonar_rules_cache.json` (Runtime) & `frontend/config/sonar_rules_cache.sample.json` (Templat)

Konfigurasi ini bertindak sebagai tembolok pencarian lokal untuk menerjemahkan kunci aturan kerentanan SonarQube secara langsung ke MITRE CWE ID. Mekanisme ini meniadakan latensi pemanggilan jaringan berulang ke SonarQube Web API selama proses pengunggahan laporan pengujian.

```json
{
  "_description": "Cache otomatis metadata dan pemetaan SonarQube Rule ke MITRE CWE ID via SonarQube API",
  "mappings": {
    "php:S1135": "CWE-546",
    "S1135": "CWE-546",
    "php:S2092": "CWE-614",
    "S2092": "CWE-614",
    "php:S3649": "CWE-89",
    "S3649": "CWE-89",
    "Web:S6819": "CWE-693"
  }

  /* Pilihan: Peta pasangan kunci-nilai antara kunci aturan SonarQube (misal 'php:S2092', 'S2092') dan MITRE CWE ID (misal 'CWE-614').
     Catatan: Digunakan oleh 'frontend/utils/sonar_cwe_mapper.py'. Penguraian memprioritaskan kunci berawalan bahasa secara tepat, beralih ke kunci tanpa awalan, lalu tag aturan dan heuristik regex, dengan menerapkan bobot prioritas untuk mendahulukan CWE spesifik dibandingkan kategori induk umum. Diisi atau diperbarui secara otomatis menggunakan 'tools/convert_sonar_to_cwe/app.py'. */
}
```

---

## Konfigurasi Manifest Ringkasan Sistem (`system_summary.json`)

### Jalur Berkas: `backend/config/system_summary.json` (Runtime) & `backend/config/system_summary.sample.json` (Templat)

Manifest ini mengagregasi metadata server esensial, konfigurasi model aktif, dan metrik dataset empiris ke dalam satu struktur JSON terpadu. Berkas ini dibuat dan diperbarui secara otomatis oleh `pipeline_engine.py` setelah siklus pelatihan selesai, serta disajikan secara publik melalui endpoint `GET /system_summary.json`. Jika berkas manifest lokal belum tersedia pada server baru, API secara otomatis menyediakan nilai cadangan berupa penanda `"N/A"`.

```json
{
  "api_title": "Model Manajemen Kerentanan Cerdas Terintegrasi",

  /* Disinkronkan secara dinamis dari 'frontend/config/app_config.json' | Catatan: Judul resmi aplikasi. */

  "api_description": "Model Intelligent Vulnerability Management: Integrasi Pemindaian SAST & DAST",

  /* Disinkronkan secara dinamis dari 'frontend/config/app_config.json' | Catatan: Deskripsi subjudul aplikasi. */

  "app_version": "1.0.0",

  /* Disinkronkan secara dinamis dari 'frontend/config/app_config.json' | Catatan: Nomor rilis versi aplikasi. */

  "active_model": "Random Forest",

  /* Disinkronkan secara dinamis dari 'ai-model/config/ai_config.json' | Pilihan: ['Random Forest'] | Catatan: Algoritma model aktif yang diterapkan. */

  "escalation_rate": 0.10,

  /* Disinkronkan secara dinamis dari 'ai-model/config/ai_config.json' | Pilihan: Bilangan desimal antara 0.00 dan 1.00 | Catatan: Faktor pengali eskalasi temuan True Positive pada korelasi hibrida. */

  "variety_cwe": 523,

  /* Pilihan: Bilangan bulat positif atau 'N/A' | Catatan: Jumlah profil kelemahan CWE unik yang berhasil diekstraksi dari 'cwe_cvss4_lookup_table.csv' menggunakan parser CSV RFC 4180. */

  "number_cvss4_records": 34194,

  /* Pilihan: Bilangan bulat positif atau 'N/A' | Catatan: Total volume rekor data empiris CVSS 4.0 yang dihimpun dalam 'cve_cvss4_dataset.csv' menggunakan parser CSV RFC 4180. */

  "last_updated": "2026-09-07"

  /* Pilihan: Format tanggal string 'YYYY-MM-DD' atau 'N/A' | Catatan: Penanda tanggal pelaksanaan pelatihan model atau pembaruan manifest terakhir. */
}
```
