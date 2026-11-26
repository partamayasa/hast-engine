# AI Model Subsystem: Pipeline Data, Pelatihan, dan Artefak Machine Learning

Direktori `ai-model/` merupakan subsistem kecerdasan buatan utama yang bertanggung jawab atas seluruh siklus hidup data (*data lifecycle*), rekayasa fitur (*feature engineering*), pelatihan model regresi *Machine Learning*, evaluasi metrik empiris, hingga ekspor artefak biner untuk inferensi kuantifikasi keparahan kerentanan berbasis standar CVSS v4.0.

Direktori ini dirancang secara modular untuk menjamin transparansi, auditabilitas, dan reproduktifitas penuh (*research reproducibility*) dalam replikasi penelitian.

---

## 1. Struktur Direktori dan Berkas

```text
ai-model/
├── artifacts/                   # Artefak biner model dan vektorizer yang siap digunakan produksi
│   ├── .gitkeep                 # Penanda Git agar direktori terlacak
│   ├── model_random_forest.pkl  # Biner model Random Forest Regressor terlatih
│   └── tfidf_vectorizer.pkl     # Biner representasi teks TF-IDF terfiting
│
├── config/                      # Konfigurasi model dan parameter operasional
│   ├── ai_config.json           # Konfigurasi aktif (hyperparameter, rasio eskalasi, skema validasi)
│   └── ai_config.sample.json    # Templat dasar konfigurasi terkontrol versi
│
├── data/                        # Korpus data primer dan hasil luaran evaluasi
│   ├── nvdcve/                  # Berkas mentah JSON National Vulnerability Database (2020-2026)
│   ├── cve_cvss4_dataset.csv    # Dataset konsolidasi hasil ekstraksi NVD beranotasi CVSS v4.0
│   ├── cwe_cvss4_lookup_table.csv # Tabel rujukan pemetaan statistik karakteristik CWE
│   ├── model_comparison_result.json # Evaluasi komparasi algoritma (RF, SVR, Ridge, dll.)
│   ├── model_evaluation_result.json # Metrik evaluasi data uji (MAE, MSE, RMSE, R2)
│   └── model_training_result.json   # Rekap histori pelatihan model aktif
│
├── preprocessing/               # Skrip ekstraksi data mentah dan pembentukan kamus CWE
│   ├── dataset_collector.py     # Parser berkas JSON NVD menjadi dataset tabular CSV
│   └── cwe_profiler.py          # Agregator modus metrik dan profil statistik CWE
│
└── training/                    # Skrip pelatihan, evaluasi, dan orkestrasi pipeline
    ├── pipeline_engine.py       # Orkestrator utama satu pintu (ekstraksi, profiling, training, manifest)
    └── train_production_model.py # Pelatihan model Random Forest dan pencatatan metrik
```

---

## 2. Deskripsi Modul dan Tanggung Jawab

### A. Subdirektori `preprocessing/`
1. **`dataset_collector.py`**:
   - Membaca seluruh berkas mentah NVD 2.0 (`nvdcve-2.0-*.json`) di dalam `data/nvdcve/`.
   - Melakukan filter entri kerentanan yang memiliki metrik resmi CVSS v4.0.
   - Mengekstrak atribut kunci: CVE ID, tanggal publikasi/modifikasi, deskripsi teks kerentanan, skor numerik CVSS v4.0, tingkat keparahan (*severity rating*), CWE ID terkait, dan vektor serangan (*Attack Vector*, dll.).
   - Menyimpan hasil ekstraksi terstandarisasi ke `data/cve_cvss4_dataset.csv`.

2. **`cwe_profiler.py`**:
   - Membaca dataset terpadu `data/cve_cvss4_dataset.csv`.
   - Mengelompokkan data berdasarkan variasi CWE ID.
   - Menghitung statistik keparahan dasar per CWE (median skor, modus metrik eksploitabilitas, frekuensi kemunculan).
   - Menghasilkan tabel rujukan cepat di `data/cwe_cvss4_lookup_table.csv` yang digunakan sebagai fallback penentu nilai dasar ketika data masukan scanner minim konteks.

### B. Subdirektori `training/`
1. **`train_production_model.py`**:
   - Melakukan pembagian data latih dan data uji secara deterministik (*random_state* terkunci).
   - Mengonversi representasi teks deskripsi kerentanan menjadi vektor numerik berbobot menggunakan TF-IDF (*Term Frequency-Inverse Document Frequency*) dengan batas `max_features` sesuai konfigurasi.
   - Melatih algoritma **Random Forest Regressor** dengan kriteria optimasi *squared error*.
   - Menghitung metrik performa regresi:
     - Mean Absolute Error (MAE)
     - Mean Squared Error (MSE)
     - Root Mean Squared Error (RMSE)
     - Koefisien Determinasi (R-squared / R2)
   - Mengekspor model terfiting ke `artifacts/model_random_forest.pkl` dan vektorizer ke `artifacts/tfidf_vectorizer.pkl`.
   - Menyimpan log hasil evaluasi ke dalam berkas JSON di `data/` dan menyinkronkannya ke tabel SQLite `database/database.db`.

2. **`pipeline_engine.py`**:
   - Berfungsi sebagai *single point of contact* (SPOC) untuk otomasi end-to-end.
   - Menjalankan secara berurutan: `dataset_collector.py` -> `cwe_profiler.py` -> `train_production_model.py`.
   - Memperbarui metadata ringkasan sistem secara otomatis ke `backend/config/system_summary.json` dan menyinkronkan timestamp ke `frontend/config/app_config.json`.

---

## 3. Parameter Konfigurasi (`config/ai_config.json`)

Berkas konfigurasi mengontrol parameter eksperimen dan operasional:

```json
{
  "active_model": "Random Forest",
  "escalation_rate": 0.10,
  "preprocessing": {
    "comparison_scheme": "k-fold",
    "max_features": 5000
  },
  "model_hyperparameters": {
    "random_forest": {
      "criterion": "squared_error",
      "n_estimators": 100,
      "max_depth": 25
    }
  }
}
```

- **`active_model`**: Arsitektur model yang aktif digunakan pada REST API (`Random Forest`).
- **`escalation_rate`**: Bobot pengali penguatan keparahan (misal `0.10` atau 10%) ketika temuan SAST terkonfirmasi oleh DAST pada titik kerentanan CWE yang sama.
- **`max_features`**: Batas dimensi fitur korpus teks TF-IDF.
- **`model_hyperparameters`**: Parameter algoritma Random Forest untuk menjamin konsistensi evaluasi.

---

## 4. Panduan Duplikasi dan Replikasi Riset

Untuk mereproduksi seluruh pipeline dari data mentah hingga model terlatih, ikuti tahapan berikut dari *root directory* proyek:

### Langkah 1: Persiapan Lingkungan dan Dependensi
Pastikan *virtual environment* Python telah aktif:
```bash
# Windows
.venv\Scripts\activate

# Linux / MacOS
source .venv/bin/activate
```

### Langkah 2: Verifikasi Data Mentah NVD
Pastikan berkas `nvdcve-2.0-2020.json` hingga `nvdcve-2.0-2026.json` telah diletakkan di dalam folder `ai-model/data/nvdcve/`.

### Langkah 3: Eksekusi Pipeline Terpadu
Jalankan satu perintah orkestrator berikut:
```bash
# Windows
python .\ai-model\training\pipeline_engine.py

# Linux / MacOS
python3 ai-model/training/pipeline_engine.py
```

### Langkah 4: Verifikasi Hasil Luaran
Setelah eksekusi selesai, pastikan artefak berikut telah diperbarui:
1. `ai-model/data/cve_cvss4_dataset.csv`
2. `ai-model/data/cwe_cvss4_lookup_table.csv`
3. `ai-model/artifacts/model_random_forest.pkl`
4. `ai-model/artifacts/tfidf_vectorizer.pkl`
5. `ai-model/data/model_evaluation_result.json`
6. `backend/config/system_summary.json`

