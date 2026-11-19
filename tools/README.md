# Tools: Utilitas Operasional, Evaluasi, dan Visualisasi Riset

Direktori `tools/` memuat skrip mandiri di luar alur aplikasi utama. Skrip ini dipakai untuk operasional (cadangan basis data), evaluasi penelitian (latensi, evaluasi DSS terhadap pakar, regresi emas), pemetaan aturan SonarQube ke CWE, dan visualisasi model. Jalankan semua perintah dari akar repositori.

---

## 1. Struktur Direktori

```text
tools/
├── backup_db/app.py             # Cadangan daring basis data SQLite + retensi
├── benchmark_latency/
│   ├── app.py                   # Latensi /predict dan /predict/hybrid (pengukuran yang dikutip di naskah)
│   └── dss_rank.py              # Latensi ranking DSS (POST /api/v1/dss/rank, tanpa menyimpan)
├── convert_sonar_to_cwe/app.py  # Memperkaya laporan SonarQube dengan CWE ID lewat SonarQube Web API
├── dss_evaluation/app.py        # Evaluasi offline ranking DSS terhadap ranking pakar
├── regression/generate_baseline.py # Membangkitkan baseline emas v1 (salinan BEKU logika v1)
├── seedir/app.py                # Pohon struktur direktori proyek
├── visualization/               # Diagram evaluasi model Random Forest (lihat README di dalamnya)
└── data/                        # Keluaran tools (gambar, teks, JSON); diberi stempel waktu Unix
```

---

## 2. Deskripsi dan Cara Menjalankan

### A. Cadangan basis data (`backup_db/app.py`)
Cadangan konsisten memakai API backup SQLite, sehingga aman dijalankan saat backend berjalan (mode WAL). Hanya memakai pustaka standar.
```bash
uv run python tools/backup_db/app.py                          # database/database.db -> database/backups/
uv run python tools/backup_db/app.py --keep 14                # simpan 14 cadangan otomatis terbaru
uv run python tools/backup_db/app.py --db path/to.db --out path/to/dir
```
Dapat dijadwalkan dengan cron atau Task Scheduler, misalnya setiap hari.

### B. Latensi inferensi (`benchmark_latency/`)
- **`app.py`** mengirim permintaan HTTP ke `/predict` dan `/predict/hybrid`, lalu mencatat waktu respons. Skrip ini mereproduksi pengukuran yang dikutip di naskah tesis, sehingga alamatnya sengaja tidak diubah (`http://localhost:8000`).
- **`dss_rank.py`** mengukur `POST /api/v1/dss/rank` tanpa menyimpan run.

Backend harus sudah berjalan di port 8000.
```bash
uv run python tools/benchmark_latency/app.py
uv run python tools/benchmark_latency/dss_rank.py --batch-id <HAST-...> --runs 20 --method TOPSIS
```
Catatan: di Windows, `localhost` dapat menambah jeda resolusi nama di setiap permintaan. Ini tercatat sebagai keputusan terbuka di [docs/CATATAN_PERUBAHAN_DSS.md](../docs/CATATAN_PERUBAHAN_DSS.md).

### C. Pengayaan laporan SonarQube dengan CWE (`convert_sonar_to_cwe/app.py`)
Membaca laporan SonarQube JSON dan mencari CWE ID setiap aturan melalui SonarQube Web API. Hasil pencarian disimpan sebagai tembolok dinamis di `frontend/config/sonar_rules_cache.json`. Keluarannya adalah laporan baru yang sudah diperkaya (`<nama>-with-cwe.json`). Host dan token dibaca dari `.env` (`SONAR_HOST_URL`, `SONAR_TOKEN`) atau dari argumen.
```bash
uv run python tools/convert_sonar_to_cwe/app.py -i scan-cli-sonar-report.json
uv run python tools/convert_sonar_to_cwe/app.py -i input.json -o output-with-cwe.json --token <TOKEN>
```

### D. Evaluasi DSS terhadap pakar (`dss_evaluation/app.py`)
Membandingkan ranking DSS yang tersimpan (`dss_runs`) dengan satu atau lebih ranking pakar. Metrik yang dihitung: Spearman, Kendall, Precision@k, dan Kendall's W bila pakarnya lebih dari satu. Ranking pakar berupa CSV berkolom `key_id`, diurutkan dari prioritas tertinggi. Skrip ini tidak menghasilkan angka tanpa ranking pakar yang nyata.
```bash
uv run python tools/dss_evaluation/app.py --list-runs
uv run python tools/dss_evaluation/app.py --run-id <uuid> --expert pakar1.csv --expert pakar2.csv --k 10
uv run python tools/dss_evaluation/app.py --run-id <uuid> --expert pakar1.csv --out tools/data/evaluasi.json
```

### E. Baseline regresi emas (`regression/generate_baseline.py`)
Salinan **beku** logika v1 (parsing, pemasangan hybrid, skoring) yang menghasilkan `tests/golden/baseline_predictions.json`. Jangan "memodernkan" berkas ini, karena tujuannya mencatat cara angka baseline tesis dihasilkan.
```bash
uv run python tools/regression/generate_baseline.py
```

### F. Pohon struktur proyek (`seedir/app.py`)
Menghasilkan pohon direktori tanpa cache, virtualenv, dan berkas sementara. Hasilnya disimpan ke `tools/data/`.
```bash
uv run python tools/seedir/app.py            # menu interaktif
uv run python tools/seedir/app.py -m 2       # mode standar naskah: root + level 1 + level 2
uv run python tools/seedir/app.py -d 3 -f    # kedalaman 3, folder saja
```

### G. Visualisasi model (`visualization/`)
Matriks konfusi 5×5, *feature importance* SHAP top-20, *beeswarm plot*, dan distribusi dataset NVD. Rinciannya ada di [visualization/README.md](visualization/README.md).
```bash
uv run python tools/visualization/app.py --all
```
