# DSS Prioritas Remediasi Kerentanan

## *Decision Support System* Berbasis *Explainable Artificial Intelligence* dan CVSS v4.0 untuk Prioritas Remediasi Kerentanan Aplikasi Web

Aplikasi ini mengintegrasikan hasil pengujian keamanan dari repositori kode sumber (**SAST - SonarQube**) dan lingkungan aplikasi waktu-nyata (**DAST - OWASP ZAP**). Algoritma **Random Forest Regressor** menguantifikasi tingkat keparahan kerentanan berdasarkan standar **CVSS v4.0**, sedangkan kesamaan kode CWE-ID antara kedua pemindai diperlakukan sebagai koroborasi, bukan verifikasi.

Sistem ini berfungsi sebagai **Sistem Pendukung Keputusan** (*Decision Support System*, DSS) bagi tim keamanan. Temuan yang terbukti di kode dan di aplikasi berjalan dikelompokkan menjadi **isu**, lalu diberi prioritas **P1–P4** beserta alasan, cara memperbaiki, lokasi terdampak, dan tenggat. Analis mencatat tindak lanjut (status, penanggung jawab, tenggat) langsung di halaman yang sama, dan setiap perubahan terekam dalam jejak audit. Perhitungan multikriteria (MCDM) bekerja di belakang layar untuk mengurutkan isu di dalam prioritas yang sama; rinciannya hanya tampil pada mode riset.

Uraian arsitektur disajikan pada [ARCHITECTURE.md](docs/ARCHITECTURE.md) dan parameter konfigurasi pada [CONFIGURATION.md](docs/CONFIGURATION.md).

---

## Fitur Utama

### Analisis Pemindaian
- **Analisis SonarQube (SAST)**
  Mengurai berkas JSON luaran API SonarQube, memetakan aturan ke CWE, dan menghitung skor keparahan secara berkelompok (*batch*).
- **Analisis OWASP ZAP (DAST)**
  Menganalisis laporan JSON OWASP ZAP dan menyaring domain di luar cakupan.
- **Korelasi Hibrida (HAST)**
  Mengorelasikan kedua pemindai berdasarkan kesamaan CWE ID dengan strategi *Left-Base* (berbasis SAST) untuk mengisolasi temuan **Positif Benar** (*True Positive*). Prioritas dieskalasi dengan laju eskalasi (*Escalation Rate*) dari `ai-model/config/ai_config.json`.
- **Transparansi Explainable AI (SHAP)**
  Menyajikan diagram *Feature Importance* dan *Beeswarm Plot* dengan urutan fitur tersinkronisasi, serta tabel dekomposisi aditif SHAP (`Base Score`, `SHAP Base Value`, `Total SHAP Positive`, `Total SHAP Negative`, `SHAP Predicted Score`).

### Pendukung Keputusan (DSS)
- **Dasbor** (halaman pembuka)
  Ringkasan satu layar:
  - angka kunci: isu terbuka, P1 terbuka, lewat tenggat, tenggat dekat, belum ditugaskan, ditutup, kesesuaian dengan rekomendasi;
  - grafik isu terbuka per prioritas dan status;
  - sebaran keparahan pada pemindaian terakhir (SAST, DAST, Hybrid);
  - CWE dengan isu terbuka terbanyak dan beban kerja per penanggung jawab;
  - daftar tenggat terdekat dan tren temuan High + Critical antarsesi.

  Setiap grafik dilengkapi tabel *Lihat data*.
- **Prioritas Perbaikan**
  Daftar kerja berisi isu (satu jenis alert OWASP ZAP + CWE, beserta semua endpoint dan berkas kode terdampak). Prioritas P1–P4 ditentukan oleh keparahan, pembuktian di kedua pemindai, dan dampak bisnis yang dinilai analis. Setiap isu memuat alasan dalam satu kalimat, cara memperbaiki (saran OWASP ZAP dan pesan SonarQube), lokasi terdampak, serta form tindak lanjut: status, penanggung jawab, tenggat, dampak bisnis, upaya, ubah prioritas, dan catatan.
- **Asal skor dan "Perlu diperiksa"** (penerapan SHAP)
  Setiap isu menampilkan rantai skornya (SAST, DAST → rata-rata → eskalasi) serta kata-kata dalam laporan yang menaikkan atau menurunkan penilaian model (SHAP). Isu yang skornya dekat batas kelas keparahan, atau yang hanya sedikit didukung bukti teks, diberi tanda **Perlu diperiksa** agar ditinjau sebelum ditindaklanjuti. Konteks ini ikut tercatat di jejak audit dan laporan Excel.
- **Riwayat Keputusan**
  Ringkasan tindak lanjut semua isu lintas pemindaian, penanda lewat tenggat, tingkat kesesuaian dengan rekomendasi, jejak audit, dan ekspor Excel. Keputusan terbawa otomatis ke pemindaian berikutnya untuk isu yang sama.
- **Pengaturan Prioritas** (mode dev)
  Aturan prioritas dalam kalimat biasa dan tenggat per prioritas. Pengaturan lanjutan menyediakan bobot urutan (TOPSIS/SAW/WP) dan AHP dengan pemeriksaan CR ≤ 0,10. AHP tersedia sebagai fitur, tetapi tidak dipakai pada penelitian tesis; bobot memakai konfigurasi awal.
- **Sensitivitas & Evaluasi DSS** (mode dev)
  Kestabilan urutan terhadap perubahan bobot kriteria dan *escalation rate*, serta perbandingan TOPSIS dengan SAW, WP, dan normalisasi vektor, diukur dengan Spearman ρ, Kendall τ, dan irisan top-k terhadap urutan dasar.
- **Akun dan Peran**
  Lima peran dengan hak berbeda, dikelola Administrator lewat dropdown di halaman **Pengguna**:

  | Peran | Untuk | Hak utama |
  | :--- | :--- | :--- |
  | Administrator (`admin`) | Pengelola sistem | Seluruh hak, termasuk mengelola pengguna dan peran |
  | Manajer Keamanan (`manager`) | Pengambil keputusan | Aturan prioritas, SLA, bobot/AHP; menerima risiko; mengubah prioritas; menghapus riwayat; ekspor |
  | Analis Keamanan (`analyst`) | Penilai temuan | Tindak lanjut (PIC, tenggat, dampak bisnis, upaya); mengubah prioritas; positif palsu/ditunda; ekspor; evaluasi |
  | Pengembang (`developer`) | Tim perbaikan | Memperbarui progres (Belum/Sedang dikerjakan/Selesai) dan catatan |
  | Auditor (`auditor`) | Pimpinan/auditor | Baca saja, termasuk jejak audit dan ekspor |

---

## Prasyarat Sistem

- **Python 3.13** (dikunci di `pyproject.toml`; `uv` dapat mengunduhnya otomatis)
- **uv** (manajer paket; dianjurkan) atau `pip`
- **Git CLI**
- **tmux** (opsional, untuk menjalankan layanan via `app.sh`)

---

## Instalasi dan Eksekusi (Lokal)

```bash
# 1. Pasang dependensi dengan versi terkunci (uv.lock). scikit-learn dikunci 1.9.1 agar artefak .pkl dapat dimuat.
uv sync

#    Alternatif tanpa uv:
#    python -m venv .venv && .venv\Scripts\activate (Windows) | source .venv/bin/activate (Linux/MacOS)
#    pip install -r requirements.txt

# 2. Salin dan isi variabel lingkungan (rahasia JWT dan akun Administrator awal), lalu buat konfigurasi DSS
#    dari templat. Backend menolak start bila backend/config/dss_config.json belum ada.
cp .env.sample .env
cp backend/config/dss_config.sample.json backend/config/dss_config.json

# 3. Tempatkan berkas mentah NVD JSON (nvdcve-2.0-2020.json s.d. 2026) di ai-model/data/nvdcve/,
#    lalu jalankan pipeline (ekstraksi dataset, profil CWE, pelatihan, sinkronisasi manifest)
uv run python ai-model/training/pipeline_engine.py

# 4. Jalankan backend (migrasi basis data berjalan otomatis saat startup)
uv run uvicorn backend.api:app --host 127.0.0.1 --port 8000
#    Mode pengembangan dengan auto-reload: tambahkan --reload

# 5. Jalankan antarmuka pada terminal terpisah, lalu buka http://localhost:8501
uv run streamlit run frontend/app.py
```

Langkah 3 hanya diperlukan untuk melatih ulang model. Artefak model yang sudah ada di `ai-model/artifacts/` langsung dipakai oleh backend.

Akun **Administrator** pertama dibuat otomatis dari `HAST_ADMIN_USERNAME` dan `HAST_ADMIN_PASSWORD` ketika tabel pengguna masih kosong. Akun lain dan perannya dibuat melalui halaman **Pengguna**.

### Rute khusus
- `?dev=true` (atau `?test_mode=true` / `?qa=true`): menampilkan halaman Riset & QA (Analisis Riset, Sensitivitas & Evaluasi DSS, Simulasi, Pengujian Black-Box)

---

## Deployment (`app.sh`)

Untuk menjalankan Backend API (port `8000`) dan Dasbor Streamlit (port `8501`) secara bersamaan di server Linux/macOS menggunakan `tmux`:

```bash
cp .env.sample .env   # isi HAST_JWT_SECRET, HAST_ADMIN_*, dan PUBLIC_API_BASE_URL (jika di balik reverse proxy)
cp backend/config/dss_config.sample.json backend/config/dss_config.json
chmod +x app.sh
./app.sh
```

Untuk mode pengembangan dengan auto-reload uvicorn, jalankan `HAST_DEV=1 ./app.sh`. Bila menggunakan *reverse proxy* (seperti Nginx/Caddy), arahkan `/` ke `http://127.0.0.1:8501` (dengan WebSocket aktif) serta `/api` dan `/sample-reports` ke `http://127.0.0.1:8000`. Cadangan basis data dapat dibuat dengan `python tools/backup_db/app.py --keep 14`.

---

## Pengujian

```bash
uv run pytest                 # seluruh tes (termasuk regresi emas, perlu artefak model)
uv run pytest -m "not slow"   # tanpa uji regresi emas
```

Uji regresi emas (`tests/test_regression_golden.py`) memastikan pipeline v2 menghasilkan skor yang identik dengan baseline `v1.0.0-tesis`. Tes yang memerlukan artefak model dilewati otomatis bila artefak tidak tersedia, misalnya di CI. Per November 2026, 151 tes lolos. Rinciannya ada di [tests/README.md](tests/README.md).

---

## Struktur Repositori

| Direktori | Isi | Dokumentasi |
| :--- | :--- | :--- |
| `backend/` | FastAPI: skoring, korelasi, DSS, keputusan, autentikasi, dasbor | [backend/README.md](backend/README.md) |
| `frontend/` | Antarmuka Streamlit (klien tipis) | [frontend/README.md](frontend/README.md) |
| `ai-model/` | Pipeline data NVD, pelatihan Random Forest, artefak model | [ai-model/README.md](ai-model/README.md) |
| `database/` | Basis data SQLite dan cadangannya | [database/README.md](database/README.md) |
| `docs/` | Arsitektur, konfigurasi, catatan perubahan v2 | [docs/README.md](docs/README.md) |
| `tests/` | Tes otomatis pytest | [tests/README.md](tests/README.md) |
| `tools/` | Cadangan DB, benchmark, evaluasi DSS, baseline emas, visualisasi | [tools/README.md](tools/README.md) |
| `sample-reports/` | Laporan sampel SonarQube dan OWASP ZAP | [sample-reports/README.md](sample-reports/README.md) |
| `logs/` | Log runtime | [logs/README.md](logs/README.md) |
