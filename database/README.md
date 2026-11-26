# Database: Penyimpanan Relasional SQLite

Direktori `database/` menyimpan basis data **SQLite** aplikasi:
- riwayat pemindaian SAST, DAST, dan korelasi hybrid;
- metadata dataset NVD dan metrik evaluasi model;
- data DSS: pengguna, run ranking, keputusan analis, dan jejak audit.

**Hanya backend yang membuka basis data** (`backend/repositories/`). Skema dikelola oleh **Alembic** (`backend/db/migrations/`). Basis data diakses dalam mode WAL sehingga berkas `database.db-wal` dan `database.db-shm` dapat muncul di sampingnya.

> `database/database.db` berisi data penelitian. Gunakan salinan untuk demo atau percobaan (`HAST_DATABASE_URL=sqlite:///path/ke/salinan.db`), dan buat cadangan sebelum menghapus data apa pun.

---

## 1. Struktur Direktori

```text
database/
├── .gitkeep          # Penanda Git agar direktori terlacak
├── database.db       # Basis data SQLite (dibuat/dimigrasikan otomatis saat backend dijalankan)
└── backups/          # Cadangan dari tools/backup_db/app.py
```

---

## 2. Tabel

Rincian kolom tersedia di `backend/db/models.py`, dan gambaran relasinya di [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) Bagian 3.

### Tabel Pemindaian & Riset

| Tabel | Isi |
| :--- | :--- |
| `scan_history` | Satu baris per temuan yang sudah diberi skor. Kolom utama: `batch_id`, `timestamp`, `scanner_type`, `key_id`, `cwe_id`, `component`, `description`, `predicted_score`, `predicted_severity`, `execution_duration`, serta atribut SHAP (`base_score`, `shap_base_value`, `shap_total_pos`, `shap_total_neg`, `absent_vocab_bias`, `shap_predicted_score`, `shap_positive`, `shap_negative`), serta `sast_description` / `dast_description` untuk baris hybrid. |
| `dataset_metadata` | Profil dataset NVD CVSS v4.0: jumlah sampel latih/uji, rasio, statistik skor, skema validasi. |
| `dataset_class_distribution` | Frekuensi dan proporsi tiap kelas keparahan (NONE, LOW, MEDIUM, HIGH, CRITICAL). |
| `model_evaluation_metrics` | Metrik model per algoritma: `accuracy`, `precision`, `recall`, `f1_score`, `mae`, `rmse`, `r2_score`, waktu latih, matriks konfusi dan *feature importance* (JSON). |

Nilai `scanner_type` di `scan_history`: `SonarQube (SAST)`, `OWASP ZAP (DAST)`, dan `Pengujian Korelasi Hybrid`. Baris hybrid adalah pasangan SAST–DAST.

### Tabel DSS, Pengguna, & Audit

| Tabel / kolom | Isi |
| :--- | :--- |
| Kolom baru `scan_history` (revisi 0002) | `issue_type`, `has_cwe_tag`, `mitigation_text`, `sast_score`, `dast_score`, `is_true_positive`, `sast_key_id`, `dast_key_id`, `sast_component`, `dast_component`, `decision_key`, `model_version` |
| `users` | Akun, hash kata sandi Argon2, peran (`admin`, `manager`, `analyst`, `developer`, `auditor`), status aktif |
| `dss_runs` | Setiap ranking yang disimpan: metode, bobot, kriteria, sumber bobot, *escalation rate*, versi model, hasil lengkap (JSON) |
| `dss_decisions` | Satu baris per isu: rekomendasi sistem, prioritas pilihan analis, status, penanggung jawab, tenggat, dampak bisnis, upaya, catatan |
| `dss_decision_events` | Jejak audit yang hanya dapat ditambah (*append-only*), termasuk konteks skor/SHAP saat keputusan dibuat |
| `alembic_version` | Revisi skema aktif (`0001` baseline, `0002` DSS, `0003` keputusan per isu) |

---

## 3. Pengelolaan

### Inisialisasi dan migrasi
Tabel dibuat dan dimigrasikan otomatis saat **backend** dijalankan (`uv run uvicorn backend.api:app`). Migrasi juga dapat dijalankan manual dengan `uv run alembic upgrade head`. Tidak perlu menjalankan skrip SQL sendiri.

### Cadangan
```bash
uv run python tools/backup_db/app.py            # database/database.db -> database/backups/
uv run python tools/backup_db/app.py --keep 14  # simpan 14 cadangan otomatis terbaru
```
Cadangan memakai API backup SQLite sehingga aman dibuat saat backend berjalan.

### Mulai dari basis data kosong
1. Buat cadangan terlebih dahulu (lihat di atas).
2. Hentikan backend dan frontend.
3. Pindahkan atau hapus `database/database.db` (beserta `-wal` dan `-shm` bila ada).
4. Jalankan backend. Skema kosong dibuat otomatis, termasuk akun Administrator awal dari `HAST_ADMIN_USERNAME` / `HAST_ADMIN_PASSWORD`.
5. Jalankan ulang pipeline model (`uv run python ai-model/training/pipeline_engine.py`) untuk mengisi kembali metadata dataset dan metrik evaluasi.

Untuk menghapus riwayat pemindaian saja, gunakan tombol **Hapus Seluruh Riwayat** di halaman SAST, DAST, atau Korelasi Hybrid (peran Manajer Keamanan atau Administrator). Keputusan DSS dan jejak audit tidak ikut terhapus.
