# Catatan Perubahan Perombakan DSS (Jalur A)

Dokumen ini mencatat setiap perubahan pada perombakan aplikasi HAST menjadi Sistem Pendukung Keputusan (*Decision Support System*, DSS) melalui Jalur A (fase 0–7). Setiap entri memuat apa yang diubah, alasan, berkas yang terdampak, hasil verifikasi, dan penyimpangan dari rencana awal. Keputusan yang masih harus ditetapkan pemilik penelitian dikumpulkan pada bagian **Keputusan Terbuka** di akhir dokumen.

- **Titik awal:** commit `ad1ea5c` (tag `v1.0.0-tesis`)
- **Tanggal pengerjaan:** 17 November 2026
- **Status commit:** seluruh perubahan berada di *working tree* dan **belum di-commit**.

---

## Fase 0 — Pembekuan Baseline

### 0.1 Tag baseline tesis
- Membuat tag beranotasi lokal `v1.0.0-tesis` pada commit `ad1ea5c` (belum di-*push*).
- **Alasan:** versi yang menghasilkan angka di naskah tesis harus tetap bisa dijalankan ulang (`git checkout v1.0.0-tesis`).

### 0.2 Cadangan basis data dan sidik jari artefak
- Menyalin `database/database.db` ke `database/backups/2026-11-17-baseline/database.db` (di-ignore git melalui pola `database/*`).
- Sidik jari SHA-256 saat baseline:

| Berkas | SHA-256 |
| :--- | :--- |
| `database/database.db` | `4a5a653e04f5fc289d127bbe2f06b4a061214fd828b84329db06c771414bade8` |
| `ai-model/artifacts/model_random_forest.pkl` | `042bf346eb7a475bc6cb60b0487bb682b41ad709973803d4e9e48253ffe8f171` |
| `ai-model/artifacts/tfidf_vectorizer.pkl` | `e442e85e0861ebd7a011a8dee6d5efc590510aaeefb21ff70049aafa117999e8` |
| `frontend/config/sonar_rules_cache.json` | `de43445c250231c713c9014c0e172caeacf5d783ad14b3ee9bba9e5b61b7fd46` |
| `ai-model/data/cwe_cvss4_lookup_table.csv` | `097e49c32c5382ee71216bd98c924b560cea8016dfd2cd4a1af179622775e5df` |

### 0.3 Penguncian dependensi (`uv`)
- **Masalah awal:** `.venv` lama dibuat dari Python 3.13 di folder lain (`F:\SecExplain Engine\.venv`, interpreter `C:\Program Files\Python313` sudah tidak ada) sehingga tidak bisa dijalankan.
- `.venv` lama **tidak dihapus**, hanya diganti nama menjadi `.venv-broken-py313/`.
- Menambahkan `pyproject.toml` + `uv.lock`, Python dikunci ke `3.13.*`. Versi paket disamakan persis dengan isi `.venv` lama, terutama **`scikit-learn==1.9.1`** karena berkas `.pkl` hanya aman dimuat dengan versi yang sama dengan saat pelatihan.
- `requirements.txt` diregenerasi dari `uv.lock` untuk pengguna `pip` (lihat Fase 6).
- **Verifikasi:** 51 tes lama lolos pada lingkungan baru (`uv run pytest`).

### 0.4 Uji regresi emas
- `tools/regression/generate_baseline.py` adalah **salinan beku** logika v1:
  - parsing `tab_sast.py` dan `tab_dast.py`;
  - *fast-path* `analysis_flow.py`;
  - pemasangan pasangan di `tab_hybrid.py`;
  - skoring `backend.engine`.
- Hasil generator disimpan di `tests/golden/baseline_predictions.json`:
  - 94 temuan SAST dan 20 temuan DAST (cocok dengan isi `database.db`);
  - 35 pasangan hybrid;
  - ER = 0.10.
- `tests/test_regression_golden.py` membandingkan pipeline v2 dengan baseline tersebut. Kesetaraannya **persis**, tanpa toleransi pembulatan.
- **Catatan:** satu-satunya perubahan pada generator setelah dibekukan adalah jalur impor `sonar_cwe_mapper`. Modul itu dipindah apa adanya dengan `git mv` (lihat 1.6).

### Temuan Fase 0 yang dicatat, tidak diubah
1. **Rumus eskalasi berbeda.**
   - `backend/engine.py` memakai `base + (10 − base) × ER`.
   - `tests/test_formatters_and_hast.py` memakai `base × (1 + ER)`.
   - Baseline emas memastikan engine yang berlaku (contoh 6.54 → 6.89).
   - Tidak ada rumus yang diubah. → Keputusan Terbuka K1.
2. **Batas kelas keparahan berbeda** antara `backend/config.calculate_severity` (0 < skor < 0.1 → NONE) dan `frontend/utils/formatters.get_severity_category` (→ LOW). → K2.
3. **Tiga set angka metrik model yang berbeda:**

| Sumber | Accuracy | R² | Tanggal |
| :--- | :--- | :--- | :--- |
| Nilai *seed* bawaan `init_db()` | 0.6707 | 0.5848 | — |
| Isi `database.db` | 0.6317 | 0.5662 | 2026-10-13 |
| `ai-model/data/model_training_result.json` | 0.6461 | 0.5796 | 2026-10-15 |

   Nilai *seed* dipertahankan apa adanya. → K3.
4. Komentar `calculate_sus_score` merujuk "Brooke (1986)", sedangkan `docs/ARCHITECTURE.md` menyebut "Brooke (1996)". → K4.
5. `CHANGELOG.md` v1.0.0 menyebut `.gitea/workflows/deploy.yaml`, tetapi berkas tersebut tidak ada di repositori.

---

## Fase 1 — Fondasi Backend

### 1.1 Dependensi baru
`sqlalchemy 2.0.58`, `alembic 1.18.x`, `pydantic-settings 2.16.3`, `pyjwt 2.15.1`, `argon2-cffi`.

### 1.2 Settings terpusat — `backend/core/settings.py`
- Semua jalur berkas, URL basis data, rahasia JWT, batas unggah, dan kredensial SonarQube dibaca dari satu kelas `Settings` (prefiks variabel lingkungan `HAST_`, juga membaca `.env`).
- **Penyimpangan dari rencana:** rencana menyebut "satu folder `config/`". Lokasi fisik berkas JSON sengaja **tidak dipindah** karena `ai-model/training/pipeline_engine.py` menulis langsung ke `backend/config/system_summary.json` dan `frontend/config/app_config.json`. Penyatuan dilakukan di tingkat kode (satu sumber jalur), bukan di tingkat folder.
- `backend/config.py` tetap menyediakan fungsi lama (`load_hybrid_escalation_rate`, `calculate_severity`, dst.); hanya konstanta jalurnya yang kini berasal dari `Settings`. `open()` kini memakai `encoding="utf-8"`.

### 1.3 Model ORM dan migrasi — `backend/db/`
- `models.py`: tabel lama dipetakan **kolom per kolom** sama dengan skema v1.
- Kolom terstruktur baru pada `scan_history`: `issue_type`, `has_cwe_tag`, `mitigation_text`, `sast_score`, `dast_score`, `is_true_positive`, `sast_key_id`, `dast_key_id`, `sast_component`, `dast_component`, `decision_key`, `model_version`.
- Kolom baru `sus_responses.ui_version`, agar hasil SUS sebelum dan sesudah UI DSS bisa dilaporkan terpisah.
- Tabel baru: `users`, `dss_runs`, `dss_decisions`, `dss_decision_events`.
- Alembic (`backend/db/migrations/`, `alembic.ini`):
  - `0001_baseline_v1` bersifat **idempoten**. Revisi ini membuat tabel lama bila belum ada dan menambah kolom lama yang hilang sehingga `database.db` v1 (yang belum punya tabel `alembic_version`) dapat diadopsi.
  - `0002_dss_structured` menambahkan kolom dan tabel baru di atas.
- `bootstrap.py` menggantikan `init_db()`: menjalankan migrasi, lalu langkah data yang **di-port persis dari v1**:
  - pemindahan tag `[BASE_SCORE]`/`[SHAP_*]` ke kolom;
  - pembersihan HTML;
  - *seed* metrik bawaan.
- Langkah data baru di `bootstrap.py`: *backfill* `mitigation_text` dari blok `[MITIGATION]`, serta `decision_key` untuk baris hybrid lama.
- SQLite berjalan dalam mode WAL dengan `foreign_keys=ON` dan `busy_timeout=5000`.
- **Verifikasi:** salinan `database.db` asli dimigrasikan. Hash SHA-256 isi kelima tabel lama **identik** sebelum dan sesudah migrasi. `mitigation_text` terisi untuk 19 dari 20 temuan DAST (satu temuan tidak memiliki teks solusi). Tes `test_legacy_v1_database_is_adopted_without_data_change` mengunci perilaku ini.

### 1.4 Aplikasi FastAPI — `backend/main.py`
- Factory `create_app(database_url, load_models)` dengan `lifespan`, menggantikan `@app.on_event("startup")` yang sudah usang.
- Router dipisah per domain di `backend/routers/v1/`: `system`, `scoring`, `findings`, `research`, `auth`, `dss`, `decisions`.
- `backend/api.py` menjadi *shim* (`from backend.main import app`) sehingga perintah `uvicorn backend.api:app` tetap berlaku.
- **Penyimpangan dari rencana:** paket router dinamai `backend/routers/`, bukan `backend/api/`. Paket bernama `backend/api/` akan menutupi modul `backend/api.py` dan merusak perintah `uvicorn` yang sudah terdokumentasi.
- **Penyimpangan lain:** `backend/engine.py` dan `backend/model_loader.py` **tidak dipindah** ke `services/`. Jalur kode skoring sengaja tidak disentuh agar regresi angka dapat dijamin; logika baru berada di `backend/services/`.
- Endpoint v1 (`/`, `/predict`, `/predict/hybrid`, `/predict/shap`, `/sample-reports/{filename}`, `/system_summary.json`) dipertahankan dengan kontrak yang sama. Endpoint baru: `/api/v1/health`.

### 1.5 Keamanan — `backend/core/security.py`, `backend/routers/deps.py`
- Hash kata sandi Argon2 dan token JWT HS256. Ada dua peran: `analyst` dan `manager`.
- Akun manajer awal dibuat otomatis dari `HAST_ADMIN_USERNAME`/`HAST_ADMIN_PASSWORD` bila tabel `users` kosong.
- `HAST_JWT_SECRET` wajib diatur di produksi; tanpa itu token hangus setiap kali server dimulai ulang (ada peringatan di log).

### 1.6 Pemindahan `sonar_cwe_mapper`
- `frontend/utils/sonar_cwe_mapper.py` dipindah ke `backend/services/parsers/sonar_cwe_mapper.py` dengan `git mv`. Hanya blok impor konfigurasi yang diganti; logika resolusi CWE tidak berubah.
- Pemakai modul ini diperbarui: `tools/convert_sonar_to_cwe/app.py`, `tests/test_sonar_cwe_mapper.py`, `tests/test_blackbox_scenarios.py`.

### 1.7 Pipeline pelatihan
- `ai-model/training/train_production_model.py` kini menyimpan metrik riset melalui `backend.repositories.research`, bukan `frontend.utils.database`.

### 1.8 Tes
- `tests/conftest.py` ditulis ulang:
  - Klien API memakai **DB sementara**. Sebelumnya `TestClient` berjalan terhadap `database/database.db` asli sehingga tes dapat mengotori data riset.
  - Fixture baru: `save_rows`, `db_url`, `manager_token`, `analyst_token`.
  - Penanda `requires_model` membuat tes otomatis dilewati bila artefak `.pkl` absen (misalnya di CI).
- `test_database.py`, `test_history_shap.py`, dan tiga tes DB di `test_blackbox_scenarios.py` dialihkan ke repositori backend. **Nama tes dan asersinya tetap.** TC-DB-03 kini menghapus melalui `history_repo.delete_batch`, bukan SQL mentah.
- `pytest.ini`: penanda `requires_model` dan `slow` didaftarkan.
- **Verifikasi:** 52 tes lolos (51 lama + 1 tes migrasi), ditambah 4 tes regresi emas yang lolos.

---

## Fase 2 — Pemindahan Logika dan Data ke Backend

### 2.1 Endpoint baru (`backend/routers/v1/findings.py`)

| Endpoint | Fungsi | Menggantikan (v1) |
| :--- | :--- | :--- |
| `POST /api/v1/ingest/sonarqube`, `/ingest/zap` | Parsing laporan + resolusi CWE + filter domain | Parsing di `tab_sast.py` / `tab_dast.py` |
| `POST /api/v1/batches` | Skoring satu batch (termasuk *fast-path* v1) + simpan | `ThreadPoolExecutor` per temuan + `save_to_history` di `analysis_flow.py` |
| `GET /api/v1/history`, `/batches`, `/batches/{id}` | Baca riwayat | `sqlite3` di `history.py`, `tab_hybrid.py`, `tab_shap_visual.py` |
| `DELETE /api/v1/batches/{id}`, `/history` | Hapus sesi / seluruh riwayat (**wajib login**) | `cb_delete_batch`, `cb_clear_all` |
| `POST /api/v1/history/shap` | Hitung **dan simpan** SHAP yang belum ada | Thread di `history.py` / `tab_shap_visual.py` yang mengimpor `backend.engine` lalu menulis SQLite |
| `POST /api/v1/correlation/preview`, `/correlation/run` | Irisan CWE *Left-Base* + skoring hybrid + simpan | `pd.merge` + pemanggilan per pasangan di `tab_hybrid.py` |
| `GET /api/v1/research/*`, `POST/GET /api/v1/sus` | Data riset dan SUS | `load_research_*`, `save_sus_response` |
| `POST /api/v1/scoring/shap/batch` | SHAP batch tanpa status | — |

### 2.2 Layanan dan repositori baru
- `backend/services/parsers/reports.py`: parser SonarQube/ZAP, dipindah dari UI dengan aturan filter yang sama.
- `backend/services/scoring.py`: skoring batch, pemasangan hybrid, pencatatan versi model (`model_version` = hash SHA-256 artefak).
- `backend/services/identity.py`: `decision_key` = SHA-256 dari `CWE|komponen SAST|komponen DAST`. Pair ID (uuid4) dibuat ulang setiap kali korelasi dijalankan sehingga tidak bisa dipakai sebagai identitas keputusan.
- `backend/repositories/history.py`: port `save_to_history` (aturan pembersihan teks sama) ditambah pengisian kolom terstruktur.
- `backend/repositories/research.py`: data riset dan SUS. `calculate_sus_score` dipindah tanpa perubahan ambang.
- Hasil hybrid kini menyimpan `sast_score`, `dast_score`, `is_true_positive`, `mitigation_text`, `sast_key_id`, `dast_key_id`, dan `decision_key` (sebelumnya tidak disimpan).

### 2.3 Frontend menjadi klien tipis
- `frontend/utils/api_client.py` ditulis ulang. Setiap panggilan memakai `timeout` dan melempar `ApiError` berpesan bahasa Indonesia; token login dikirim otomatis. Di v1, `hit_hybrid_api` dan `hit_shap_api` tidak memakai `timeout`.
- **`frontend/utils/database.py` dihapus** (`git rm`). Tidak ada lagi `sqlite3` di `frontend/`.
- Komponen yang dialihkan ke API:
  - `analysis_flow.py`, `tab_sast.py`, `tab_dast.py`;
  - `history.py`, `dialogs.py`, `tab_hybrid.py`;
  - `tab_shap_visual.py`, `tab_analysis.py`, `page_sus_survey.py`.
- **Penyimpangan dari rencana:** tab dev **Simulasi** dan **Black-Box** masih menjalankan fungsi backend/model di dalam proses. Kedua tab ini adalah harness riset/QA yang cerminnya ada di pytest, dan hanya tampil pada mode dev. Konsekuensinya, kedua tab mensyaratkan frontend dan backend berada di host yang sama (berlaku pada deployment saat ini dan pada image Docker bersama).
- **Perbaikan:** skenario TC-DB-01/03 di tab Black-Box v1 **menulis lalu menghapus baris uji di `database.db` riset**. Di v2 keduanya berjalan pada DB sementara yang terisolasi.
- `tab_analysis.py` masih membaca berkas riset `ai-model/data/*.json` dan `cwe_cvss4_lookup_table.csv` langsung dari disk, tidak lewat API. Ini dicatat sebagai sisa pekerjaan (berkas statis hasil pipeline, bukan basis data).
- Unggahan laporan di-*cache* per isi berkas (`ingest_report_cached`) agar Streamlit tidak mengunggah ulang berkas 16 MB setiap kali halaman dijalankan ulang.
- Perubahan perilaku yang disengaja: menghapus riwayat kini **memerlukan login**, dan daftar respons SUS (memuat nama responden) memerlukan login. Pengisian SUS tetap publik.

### 2.4 Verifikasi
- Uji regresi emas lolos melalui jalur baru: parser backend → skoring batch → repositori → korelasi dari DB. Ke-94 skor SAST, 20 skor DAST, dan 35 pasangan hybrid (skor individual, base, hybrid, kelas, status TP, nilai SHAP) **identik** dengan baseline v1.

---

## Fase 3 — Inti DSS

### 3.1 Modul `backend/dss/` (fungsi murni, tanpa I/O dan tanpa model ML)
- `mcdm.py`: SAW, TOPSIS, dan WP ditulis eksplisit tanpa pustaka MCDM pihak ketiga agar setiap langkah dapat dirujuk. Kasus tepi ditangani:
  - kolom nol;
  - kriteria *cost* bernilai 0 (SAW memakai normalisasi min-max);
  - alternatif identik (TOPSIS memberi C = 0.5);
  - pergeseran skala WP.

  Fungsi `rank_order` memberi peringkat deterministik dengan *tie-break* eksplisit.
- `criteria.py`: membangun matriks keputusan dari pasangan hybrid tersimpan:
  - C1 skor hybrid;
  - C2 status TP;
  - C3 eksploitabilitas dan C4 dampak, dari metrik CVSS 4.0 pada `cwe_cvss4_lookup_table.csv`;
  - C5 penyebaran CWE dalam sesi;
  - C6 kekritisan aset;
  - C8 upaya remediasi.

  Nilai yang diimputasi atau memakai default ditandai per alternatif.
  - *Encoding* ordinal metrik CVSS dinyatakan sebagai **asumsi perancang** karena CVSS 4.0 tidak memakai bobot numerik per metrik.
  - Kolom `sub_*` di lookup selalu bernilai NONE sehingga tidak dipakai.
  - Kriteria C7 (paparan/DAST hadir) **tidak** dipakai karena bernilai konstan pada pasangan hybrid.
- `escalation.py`: rumus eskalasi engine dinyatakan ulang sebagai fungsi murni untuk sensitivitas ER. `backend/engine.py` **tidak diubah**. Tes membuktikan fungsi ini mereproduksi ke-35 skor hybrid baseline emas.
- `recommender.py`: aturan berurutan (aturan pertama yang cocok menang, ID aturan dicatat). Aksi dan status berlabel Indonesia. SLA diambil dari konfigurasi; nilai `null` berarti tanpa tenggat.
- `service.py`: orkestrasi matriks → MCDM → rekomendasi → penjelasan → persistensi. Peringatan otomatis muncul bila:
  - C1 dan C3/C4 sama-sama aktif (tumpang tindih informasi CVSS);
  - ada nilai hasil imputasi;
  - lookup tidak tersedia;
  - status TP tidak tersimpan (sesi v1).
- `config.py` + `backend/config/dss_config.sample.json`: konfigurasi divalidasi saat dimuat. Bobot dalam sampel **diberi label tegas sebagai nilai contoh, bukan hasil penelitian**, dan semua `sla_days` bernilai `null`.

### 3.2 Endpoint DSS (`backend/routers/v1/dss.py`)
- `GET/PUT /api/v1/dss/config`: menyimpan konfigurasi hanya untuk manajer.
- `POST /api/v1/dss/rank`: pratinjau publik dengan `persist=false`; penyimpanan memerlukan login agar pelaku tercatat.
- `GET /api/v1/dss/runs`, `/runs/{id}`: setiap run menyimpan metode, bobot, sumber bobot, hash konfigurasi, ER, versi model, dan hasil lengkap. Tujuannya reproduksibilitas.

### 3.3 Halaman "Rekomendasi Keputusan" (`frontend/components/page_dss_recommendation.py`)
- Tabel peringkat memuat nilai preferensi, rekomendasi, aturan, status keputusan, dan penyumbang utama.
- Penjelasan per alternatif: kontribusi setiap kriteria, nilai yang diimputasi, dan saran mitigasi OWASP ZAP yang diberi label sumbernya.
- Ekspor CSV dan tombol simpan.

### 3.4 Temuan dari data sampel
- Ke-35 pasangan sampel **seluruhnya berstatus True Positive** sehingga C2 konstan dan ranking **tidak sensitif terhadap ER** (ρ = 1.0 untuk ER 0.05–0.25). Penyebabnya, eskalasi bersifat monoton bila diterapkan ke semua alternatif. Sensitivitas ER baru bermakna pada sesi yang memuat pasangan bukan TP.
- Pada contoh hitung tangan, SAW dan TOPSIS menghasilkan peringkat pertama yang berbeda. Hal serupa muncul pada data sampel: TOPSIS berbeda dengan SAW/WP. Ini menjadi alasan untuk melaporkan perbandingan metode.

---

## Fase 4 — Alur Keputusan

- **Autentikasi dan peran** (lihat 1.5), panel login di sidebar (`frontend/components/auth_panel.py`), dan halaman **Pengguna** khusus manajer.
- **Tabel `dss_decisions`** menyimpan satu keputusan aktif per `decision_key`. `upsert_recommendation` hanya memperbarui kolom rekomendasi; kolom milik analis (`chosen_action`, `status`, `reason`, `asset_criticality`, `remediation_effort`) **tidak pernah ditimpa**. Masukan kekritisan aset dan upaya remediasi dari analis dipakai pada ranking berikutnya.
- **Jejak audit `dss_decision_events`** bersifat *append-only*. Peristiwa `RECOMMENDED`, `DECIDED`, dan `UPDATED` dicatat beserta pelaku, run, dan diff perubahan.
- **Endpoint** (`backend/routers/v1/decisions.py`):
  - `GET /api/v1/decisions`;
  - `PUT /api/v1/decisions/{key}` (wajib login; status Risiko Diterima, Positif Palsu, dan Ditunda wajib disertai alasan);
  - `GET /{key}/events`;
  - `GET /export.xlsx`;
  - `GET /agreement` (rasio persetujuan rekomendasi).
- **Halaman "Log Keputusan"**: `st.data_editor` untuk keputusan, status, alasan, kekritisan, upaya, dan tenggat. Halaman ini juga menampilkan metrik tingkat persetujuan, ekspor Excel, dan jejak audit per temuan.

---

## Fase 5 — AHP, What-if, Sensitivitas

- `backend/dss/ahp.py`: bobot dari eigenvektor utama, λmaks, CI, CR dengan tabel RI Saaty (n ≤ 10), validasi matriks resiprokal, dan agregasi pakar dengan rata-rata geometrik.
- `POST /api/v1/dss/ahp`: menghitung bobot untuk siapa saja; menyimpan ke konfigurasi hanya manajer, dan hanya bila **CR ≤ 0,10**. Sumber penilaian dicatat.
- `backend/dss/sensitivity.py`: perturbasi bobot satu kriteria ±10/20/30% (kriteria lain diskalakan proporsional), dibandingkan dengan baseline memakai Spearman ρ, Kendall τ, irisan top-k, dan perubahan peringkat 1. Sensitivitas ER memakai `escalation.py`, tanpa memanggil model ML.
- Endpoint: `POST /api/v1/dss/sensitivity`, `POST /api/v1/dss/sensitivity/escalation-rate`.
- UI:
  - panel *what-if* (slider bobot, ER, metode) dengan kolom Δ Peringkat di halaman Rekomendasi;
  - halaman **Bobot Kriteria** (AHP dengan skala Saaty, metode bawaan, bobot manual, kebijakan SLA);
  - halaman dev **Sensitivitas & Evaluasi DSS** (grafik sensitivitas, perbandingan metode, evaluasi terhadap ranking pakar).

### Verifikasi Fase 2–5
- `pytest`: **107 tes lolos**:
  - 51 tes lama;
  - 1 tes migrasi;
  - 4 tes regresi emas;
  - 36 tes logika DSS murni (`test_dss_core.py`);
  - 15 tes API DSS/keputusan/autentikasi (`test_dss_api.py`).

  Nilai rujukan SAW/TOPSIS di `test_dss_core.py` dihitung dengan implementasi Python polos yang terpisah dari kode produksi:
  - SAW = [0.844444, 0.533333, 0.866667];
  - TOPSIS = [0.780169, 0.30848, 0.69152].
- Uji ujung-ke-ujung lewat API memakai laporan sampel: unggah → batch (94/20) → korelasi (35) → ranking → keputusan → ranking ulang. Keputusan analis tetap utuh, dan jejak audit berisi `RECOMMENDED`, `DECIDED`.
- **Render headless seluruh halaman Streamlit** (`streamlit.testing.v1.AppTest`) terhadap backend yang berjalan, sebagai tamu maupun manajer: **0 exception, 0 `st.error`** di 12 halaman. Klik tombol "Jalankan Evaluasi Korelasi Hybrid", "Simpan Ranking & Rekomendasi", dan login sidebar juga berhasil.
- Belum diverifikasi: pengeditan sel `st.data_editor` di Log Keputusan (AppTest belum mendukung simulasi edit sel). Logika simpannya diuji melalui endpoint `PUT /api/v1/decisions/{key}`.

---

## Fase 6 — Operasional

| Berkas | Isi |
| :--- | :--- |
| `Dockerfile`, `.dockerignore` | Satu image untuk API dan UI (Python 3.13 + uv, dependensi dari `uv.lock`, pengguna non-root). Data runtime tidak dimasukkan ke image. |
| `docker-compose.yml` | Layanan `api` (satu worker; SQLite WAL), `ui`, dan `caddy` (HTTPS otomatis). `database/`, artefak model, data riset, dan konfigurasi di-*mount* dari host. Pemeriksaan kesehatan memakai `/api/v1/health`. |
| `deploy/Caddyfile` | Rute `/api/*`, `/sample-reports/*`, `/predict*`, `/system_summary.json` → API; selainnya → Streamlit. `/docs` tidak diekspos; header HSTS/nosniff. |
| `deploy/systemd/hast-api.service`, `hast-ui.service` | Alternatif tanpa Docker; tanpa `--reload`. |
| `.gitea/workflows/ci.yaml` | `uv lock --check` + `uv sync --frozen` + `pytest` pada setiap *push*/PR. |
| `.gitea/workflows/deploy.yaml` | **Hanya manual** (`workflow_dispatch`) via SSH: cadangan DB → `docker compose up -d --build`. Memerlukan *secret* `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_KEY`, dan `DEPLOY_PATH`. |
| `tools/backup_db/app.py` | Cadangan daring SQLite (API backup), `PRAGMA integrity_check`, retensi `--keep N`; hanya pustaka standar. |
| `.env.sample` | Seluruh variabel lingkungan beserta penjelasannya. `.gitignore` diberi pengecualian `!.env.sample`. |
| `app.sh.sample` | Memakai `uv`; `--reload` hanya aktif bila `HAST_DEV=1`. `app.sh` lokal milik pengguna tidak diubah. |
| `requirements.txt` | Diekspor dari `uv.lock` (81 paket, termasuk `pytest`). |
| `frontend/utils/config.py` | `PUBLIC_API_BASE_URL` untuk tautan unduhan sampel di browser. Di Docker, `API_BASE_URL=http://api:8000` tidak dapat diakses dari browser. |
| `.gitignore` | `dss_config.json`, `.venv-*/`, `!.env.sample`. |

**Verifikasi:**
- `uv lock --check` lolos.
- Alat cadangan diuji (cadangan + retensi) dan dikunci oleh `tests/test_ops_tools.py`.
- Simulasi CI tanpa artefak model (`HAST_RF_MODEL_PATH`/`HAST_TFIDF_PATH` diarahkan ke berkas yang tidak ada): **95 lolos, 14 dilewati, 0 gagal**.
- **Belum diverifikasi:** Docker tidak terpasang di mesin pengembangan sehingga `docker compose build/up`, Caddy, unit systemd, dan kedua workflow Gitea **belum pernah dijalankan**. Berkas-berkas tersebut perlu diuji di server staging sebelum dipakai.

---

## Fase 7 — Alat Evaluasi

- `backend/dss/evaluation.py` ditambah **Kendall's W** (kesepakatan antarpakar, beserta aproksimasi χ²) dan tes kasus ekstremnya (W = 1 untuk ranking identik, W = 0 untuk dua ranking terbalik).
- `POST /api/v1/dss/evaluate` dan tab "Evaluasi vs Pakar" di halaman riset membandingkan run DSS tersimpan dengan ranking pakar. Pembanding *baseline* adalah urutan skor hybrid saja, tanpa MCDM.
- `tools/dss_evaluation/app.py` adalah CLI offline untuk bab hasil. Fiturnya:
  - `--list-runs`;
  - evaluasi satu atau beberapa pakar;
  - Kendall's W;
  - keluaran JSON.

  Alat ini **tidak menghasilkan angka apa pun tanpa ranking pakar nyata**.
- `tools/benchmark_latency/dss_rank.py`: benchmark latensi `/api/v1/dss/rank`. Pada mesin pengembangan, dengan 35 alternatif dan TOPSIS, medianya **16,91 ms** (n = 20). Berkas `tools/benchmark_latency/app.py` (Listing 4.5 naskah) **tidak diubah**.
- **Temuan:** permintaan ke `http://localhost:8000` di Windows memakan ~2,05 detik per permintaan karena *fallback* IPv6, sedangkan `127.0.0.1` hanya ~17 ms. Lihat K5.
- SUS: kolom `ui_version` (`v2-dss` untuk respons baru; respons lama ditampilkan sebagai `v1`) memungkinkan pelaporan putaran SUS sebelum dan sesudah DSS secara terpisah. **Putaran SUS v2 belum dilakukan.**

---

## Fase 8 — DSS Praktis untuk Pengguna (v2.1)

**Latar belakang.** Saat dicoba, DSS hasil fase 3–5 sulit dipahami. Pemeriksaan pada sesi `HAST-1794897579` (35 pasangan) menemukan empat penyebab:
1. **Konfigurasi contoh keliru.** Aturan kekritisan aset berbasis pola path (`docs`/`assets` → 2, `login` → 5) mengenai folder `docs-assets/` milik proyek yang dipindai. Akibatnya ketujuh temuan HIGH terlempar ke peringkat 27–32, dan sebuah temuan MEDIUM menjadi peringkat 1.
2. **Ranking dan rekomendasi bertentangan.** Peringkat 1 (MEDIUM) direkomendasikan "Rencanakan", sedangkan peringkat 2 (HIGH) "Remediasi Terjadwal".
3. **Satuan keputusan keliru.** Ke-35 baris hanya berasal dari 5 endpoint DAST; 20 baris di antaranya adalah satu masalah CSP yang diulang untuk 20 berkas PHP, dan hanya ada 11 nilai preferensi yang berbeda.
4. **Bahasa peneliti.** Pengguna melihat "nilai preferensi", kode aturan, istilah *benefit/cost*, kotak peringatan metodologis, Pair ID acak, kode aksi `REMEDIATE_NOW`, dan alur yang tersebar di tiga halaman.

**Perubahan:**

| Area | Perubahan |
| :--- | :--- |
| Satuan keputusan | `backend/dss/issues.py` (baru, fungsi murni). Pasangan SAST–DAST dikelompokkan menjadi **isu** = satu jenis alert OWASP ZAP + CWE, dengan seluruh endpoint dan berkas sebagai bukti. Kode isu `ISU-XXXXXX` stabil lintas pemindaian (hash `CWE|alert`). Skor isu = skor pasangan tertinggi; status terbukti = salah satu pasangan terbukti; C5 = jumlah lokasi terdampak. Sesi demo: **35 pasangan → 8 isu**. |
| Prioritas | Aturan menghasilkan tingkat **P1–P4** (Segera, Terjadwal, Direncanakan, Pantau) dengan kondisi baru `min_business_impact`. Urutan akhir: prioritas (bisa ditetapkan ulang oleh analis) → skor urgensi MCDM di dalam prioritas → skor keparahan. MCDM **tidak lagi bisa** menaikkan isu P3 di atas P1, sehingga urutan dan tindakan tidak pernah bertentangan. |
| Konfigurasi bawaan | Aturan pola path dihapus; dampak bisnis netral (Sedang) sampai dinilai analis. Label faktor diganti bahasa sehari-hari. Aturan prioritas memuat teks penjelasan. SLA diberi nilai awal 7/30/90 hari/tanpa tenggat untuk P1–P4, dengan label tegas bahwa nilai ini titik awal, bukan hasil penelitian maupun standar industri. |
| Penjelasan | Satu kalimat berbahasa biasa per isu: prioritas, keparahan, bukti (berapa berkas dan endpoint), dan dampak bisnis. Faktor pendorong urutan hanya disebut bila isu itu **benar-benar di atas median** isu lain; faktor yang nilainya sama untuk semua isu (misalnya dampak bisnis yang belum dinilai) tidak pernah dijadikan alasan. |
| Data keputusan | Revisi Alembic `0003_issue_decisions`: kolom `title` dan `owner` (penanggung jawab) pada `dss_decisions`. Keputusan terbawa ke pemindaian berikutnya untuk isu yang sama. |
| Metrik persetujuan | Didefinisikan ulang: dari isu yang sudah ditindaklanjuti analis, porsi yang tetap memakai prioritas rekomendasi. Definisi lama hanya menghitung isu yang prioritasnya diubah, sehingga selalu 0%. |
| Halaman | **Prioritas Perbaikan** (halaman pembuka; menggantikan "Rekomendasi Keputusan" dan "Log Keputusan") berupa kartu isu dengan tab *Cara memperbaiki* (saran ZAP + pesan SonarQube), *Lokasi terdampak*, *Tindak lanjut* (status, PIC, tenggat, dampak bisnis, upaya, ubah prioritas, catatan), dan *Riwayat*. **Riwayat Keputusan** menjadi ringkasan baca-saja dan jejak audit. **Pengaturan Prioritas** menampilkan aturan dalam kalimat dan tenggat per prioritas; bobot, metode, dan AHP pindah ke "Pengaturan lanjutan". Detail MCDM dan catatan metodologis hanya tampil di mode riset (`?dev=true`). Menu dikelompokkan menjadi "Keputusan" dan "Data Pemindaian" (langkah 1–3). |

**Verifikasi:**
- `pytest`: **116 tes lolos**, termasuk uji regresi emas (skor model tetap identik dengan v1). Tes baru mengunci:
  - pengelompokan isu;
  - HIGH tidak pernah di bawah MEDIUM;
  - dampak bisnis Tinggi menaikkan HIGH ke P1;
  - penjelasan tidak menyebut faktor konstan;
  - perubahan prioritas oleh analis mengubah urutan;
  - metrik persetujuan menghitung "ikuti rekomendasi".
- Tiga tes lama diubah karena perubahan desain yang disengaja: revisi skema 0003, nama field `why`, dan SLA bawaan.
- Render headless semua halaman baru (tamu, manajer, mode riset): 0 exception, 0 error. Penyimpanan tindak lanjut lewat form diuji lalu dikembalikan pada DB demo.

---

## Fase 9 — Peran dan Hak Akses (RBAC)

**Permintaan:** peran pengguna dijadikan dropdown dan ditambah peran yang relevan.

**Perubahan:**
- `backend/core/roles.py` (baru) adalah satu-satunya sumber peran dan hak akses (11 hak). Kunci `manager`/`analyst` dari v2.0 dipertahankan agar akun lama tetap berlaku.

| Peran | Untuk | Hak utama |
| :--- | :--- | :--- |
| Administrator (`admin`) | Pengelola sistem | Seluruh hak, termasuk mengelola pengguna dan peran |
| Manajer Keamanan (`manager`) | Pengambil keputusan | Aturan prioritas, SLA, bobot/AHP; menerima risiko; mengubah prioritas; menghapus riwayat; ekspor |
| Analis Keamanan (`analyst`) | Penilai temuan | Tindak lanjut (PIC, tenggat, dampak bisnis, upaya); mengubah prioritas; positif palsu/ditunda; ekspor; evaluasi |
| Pengembang (`developer`) | Tim perbaikan | Memperbarui progres (Belum/Sedang dikerjakan/Selesai) dan catatan |
| Auditor (`auditor`) | Pimpinan/auditor | Baca saja, termasuk jejak audit, ekspor, dan rekap SUS |

- Penegakan di backend (`require_permission`) untuk setiap endpoint yang mengubah data:
  - pengaturan/AHP: `settings.manage`;
  - hapus riwayat: `history.delete` (**Analis tidak lagi boleh menghapus riwayat**);
  - simpan ranking: `dss.save_run`;
  - ekspor: `report.export`;
  - evaluasi: `research.evaluate`;
  - rekap SUS: `sus.read`;
  - kelola pengguna: `users.manage` (sebelumnya Manajer).
- Pemeriksaan **per kolom** pada pembaruan keputusan:
  - PIC, tenggat, dampak bisnis, dan upaya memerlukan `decision.triage`;
  - ubah prioritas memerlukan `decision.override_priority`;
  - "Risiko diterima" memerlukan `decision.accept_risk`;
  - status progres dan catatan boleh diubah dengan `decision.update_progress`.

  Hanya kolom yang benar-benar berubah yang diperiksa, karena form UI mengirim semua kolom.
- Endpoint baru: `GET /api/v1/roles` (katalog peran) dan `PATCH /api/v1/users/{username}` (ubah peran, status aktif, nama). Login dan `/auth/me` kini mengembalikan label peran serta daftar hak.
- Pengaman: sistem selalu menyisakan minimal satu Administrator aktif, dan pengguna tidak dapat menonaktifkan akunnya sendiri.
- Akun awal dari `HAST_ADMIN_USERNAME` kini berperan Administrator (sebelumnya Manajer).
- UI:
  - halaman **Pengguna** menampilkan tabel dengan kolom **Peran berupa dropdown** (juga Aktif dan Nama lengkap) yang bisa disunting langsung, form tambah akun dengan dropdown 5 peran, dan tabel penjelasan hak tiap peran;
  - form tindak lanjut, tombol hapus riwayat, pengaturan, ekspor, dan evaluasi menyesuaikan hak peran yang login.

**Verifikasi:**
- `pytest`: **133 tes lolos**, termasuk 17 tes RBAC baru (`tests/test_rbac.py`) dan uji regresi emas.
- Dua tes lama disesuaikan dengan aturan baru:
  - Analis menghapus riwayat kini 403;
  - uji "wajib alasan" memakai status Positif palsu, karena Analis tidak berhak atas Risiko diterima.
- Pemeriksaan UI per peran pada DB demo (Administrator, Manajer, Analis, Pengembang, Auditor): 0 exception, 0 error; opsi status dan kunci isian sesuai peran.
- Di DB demo, akun `admin` dinaikkan menjadi Administrator, dan dibuat akun contoh `manajer`, `analis`, `pengembang`, dan `auditor`.

---

## Fase 10 — SHAP di dalam DSS

**Tujuan:** SHAP menjelaskan **skor keparahan model**, sedangkan skor itulah yang menentukan P1–P4. Karena itu, di dalam DSS SHAP dipakai untuk membantu analis menilai *"apakah skor ini layak dipercaya sebelum bertindak"*. SHAP **tidak** dijadikan kriteria MCDM, karena itu sama dengan menghitung skor yang sama dua kali.

**Kejujuran penjelasan:** SHAP di aplikasi ini menguraikan prediksi model atas teks **gabungan** SAST+DAST (`shap_predicted_score`). Skor hybrid yang dipakai DSS adalah rata-rata dua prediksi terpisah ditambah eskalasi. Keduanya ditampilkan terpisah:
- **rantai skor**, misalnya "SAST 7.27 dan DAST 6.73 → rata-rata 7.00 → +0.30 karena terbukti di kedua pemindai = 7.30";
- **faktor teks** yang memengaruhi penilaian model.

UI menyebut selisih keduanya secara terbuka.

**Perubahan:**
1. `backend/dss/explain.py` (baru, fungsi murni): rantai skor, ringkasan SHAP (kata penaik/penurun, titik awal model, pergeseran oleh kata, porsi tak terjelaskan), alasan model satu kalimat, dan penanda **"Perlu dicek"**.
   - `aggregate_issues` menyimpan pasangan representatif (pasangan yang menentukan skor isu).
   - Setiap item ranking membawa `score_explanation` dan `needs_review`.
   - Ringkasan antrean menghitung `needs_review`.
2. Penanda "Perlu dicek" adalah **heuristik** (bukan ukuran statistik) yang dapat diatur di `dss_config.review`:
   - skor berjarak ≤ `threshold_margin` (0,3) dari batas kelas keparahan; atau
   - jumlah |SHAP| kata yang hadir < `min_text_evidence` (0,5), artinya skor sebagian besar hanyalah nilai rata-rata model; atau
   - SHAP tidak tersedia.
3. Jejak audit: saat status atau prioritas diubah, backend melampirkan `konteks_model` (asal skor, alasan model, penanda, prioritas rekomendasi) dari **snapshot run terakhir di server**, bukan dari kiriman browser. `GET /decisions/{key}/events` memisahkannya sebagai `model_context`.
4. Ekspor Excel tindak lanjut ditambah kolom *Asal Skor*, *Alasan Model (SHAP)*, dan *Perlu Dicek*. Ekspor CSV antrean juga mendapat kolom serupa.
5. UI Prioritas Perbaikan:
   - lencana "Perlu dicek" pada kartu;
   - metrik dan filter "Perlu dicek";
   - tab baru **Asal skor**;
   - kotak "Pertimbangan sebelum memutuskan" di atas form tindak lanjut;
   - kolom "Konteks model saat itu" di tab Riwayat dan halaman Riwayat Keputusan.

**Temuan pada data demo:**
- 4 dari 8 isu ditandai "Perlu dicek", termasuk ketiga isu P2 (HIGH).
- Ketiga isu P2 baru masuk kelas HIGH karena eskalasi +0,30 dari skor dasar 6,77–7,00. Bukti teksnya juga lemah (pergeseran oleh kata 0,07–0,47); misalnya *Timestamp Disclosure* didorong terutama oleh kata generik "code".
- *Cookie No HttpOnly Flag* (6,90) berada 0,10 di bawah batas HIGH.

**Verifikasi:**
- **146 tes lolos**, termasuk 13 tes baru di `tests/test_dss_explain.py`:
  - rantai skor;
  - penanda dekat batas dan bukti lemah;
  - SHAP tidak tersedia;
  - ambang yang dapat dikonfigurasi;
  - snapshot konteks model di jejak audit;
  - kolom ekspor.
- Render halaman per peran (Administrator, Analis dengan mode riset, Pengembang, Auditor, tamu): 0 exception, 0 error.

---

## Fase 11 — Standar Bahasa Kode

**Permintaan:** seluruh komentar kode memakai standar dokumentasi bahasa Indonesia, dan semua variabel ditulis dalam bahasa Inggris.

**Cara kerja:**
- Inventarisasi memakai `tokenize` (komentar) dan AST (docstring dan identifier) pada seluruh berkas Python proyek. `.venv`, `.agents`, dan `.claude` dikecualikan.
- Hasil awal:
  - 231 komentar dan 210 docstring berbahasa Inggris, ditambah 308 komentar "netral" yang diperiksa manual;
  - 27 identifier berbahasa Indonesia;
  - kunci data internal berbahasa Indonesia.
- Penggantian dilakukan dengan skrip yang hanya menyentuh token komentar pada baris yang tercatat dan literal docstring pada posisi AST-nya, sehingga string kode tidak ikut berubah. Setiap berkas divalidasi ulang dengan `ast.parse` sebelum ditulis.

**Konvensi dokumentasi yang dipakai:**
- bahasa Indonesia baku (EYD V);
- kalimat pembuka docstring berbentuk verba aktif;
- bagian terstruktur `Parameter:` / `Mengembalikan:`;
- istilah teknis mapan dipertahankan;
- metadata alat (Alembic `Revision ID`, `# noqa`, `# pragma`) dan perintah contoh tidak diterjemahkan.

**Perubahan:**
1. **Komentar dan docstring:** 590 item di 86 berkas diterjemahkan.
   - Satu docstring yang sudah tidak akurat diperbaiki sekaligus: `tab_shap_visual` masih menyebut "membaca dari SQLite", padahal sejak v2 melalui API.
   - Docstring regex di `sonar_cwe_mapper.resolve_sonar_cwe` dijadikan raw string. Ini menghilangkan `SyntaxWarning: invalid escape sequence '\d'` yang sudah ada sejak kode asli.
   - Dua `description=` Pydantic berbahasa Inggris diterjemahkan.
2. **Identifier:**

| Lama | Baru | Berkas |
| :--- | :--- | :--- |
| `skor_akurasi`, `skor_presisi`, `skor_recall`, `skor_f1`, `skor_mae`, `skor_rmse`, `skor_r2` | `accuracy_value`, `precision_value`, `recall_value`, `f1_value`, `mae_value`, `rmse_value`, `r2_value` (akhiran `_value` agar tidak menimpa fungsi scikit-learn yang diimpor) | `ai-model/training/train_production_model.py` |
| `matriks_cm` | `confusion_matrix_values` | idem |
| `get_modus` | `get_mode` | `ai-model/preprocessing/cwe_profiler.py` |
| 20 nama tes black-box, mis. `test_tc_hyb_02_pencocokan_celah_keamanan_cwe` | mis. `test_tc_hyb_02_cwe_based_vulnerability_matching`; **kode TC dan docstring kasus uji tetap**, sehingga keterlacakan ke *Skenario Pengujian Artefak Tesis* terjaga | `tests/test_blackbox_scenarios.py` |

3. **Kunci data internal:**
   - `konteks_model` → `model_context`;
   - `asal_skor` → `score_origin`;
   - `alasan_model` → `model_reason`;
   - `perlu_dicek` → `review_notes`;
   - `prioritas_rekomendasi` → `recommended_priority`;
   - diff `dari`/`menjadi` → `from`/`to`;
   - kode imputasi `cwe_tidak_ada_di_lookup`/`tidak_tersimpan_v1`/`default_konfigurasi` → `cwe_not_in_lookup`/`not_stored_v1`/`config_default`.

   Jejak audit yang sudah tersimpan dengan kunci lama awalnya dinormalkan saat dibaca; sejak Fase 14 datanya ditulis ulang oleh migrasi `0004_english_payload_keys` dan penerjemah kunci lama dihapus.

**Tidak diubah (sengaja):**
- teks yang tampil ke pengguna (label UI, nama kolom ekspor seperti "Tingkat Keparahan", pesan galat);
- kunci tampilan v1 pada `load_class_distribution` / `load_all_sus_responses`, yang berfungsi sebagai label kolom tabel;
- `import sys` ganda di `train_production_model.py` (temuan pyflakes yang sudah ada sejak kode asli).

**Verifikasi:**
- Pemindaian ulang: **0 identifier berbahasa Indonesia**. Sebelas item yang masih berlabel "en" oleh heuristik ternyata positif palsu, misalnya "MODUL **A**", "what-**if**", dan label kode `# is_dast`.
- `compileall` tanpa `SyntaxWarning`, dan pyflakes tidak menemukan nama tak terdefinisi.
- **147 tes lolos**, termasuk uji regresi emas dan tes baru untuk normalisasi kunci jejak audit lama.
- Render ulang halaman per peran: 0 exception, 0 error.

---

## Fase 12 — Dasbor Visualisasi

**Permintaan:** fitur visualisasi dasbor yang berisi informasi penting.

**Perubahan:**
1. **Logika murni** `backend/dss/dashboard.py` → `build_summary(decisions, batch_stats)`. Fungsi ini hanya merangkum data yang sudah ada; tidak ada skor atau prioritas baru yang dihitung.
   - Angka kunci:
     - isu total, terbuka, P1 terbuka, sedang dikerjakan;
     - lewat tenggat, tenggat ≤ 7 hari, belum ditugaskan, bertanda "Perlu dicek";
     - ditutup beserta porsinya;
     - kesesuaian dengan rekomendasi, memakai definisi yang sama dengan `/decisions/agreement`.
   - Isu per prioritas efektif × status.
   - CWE dengan isu terbuka terbanyak, beban kerja per penanggung jawab, dan daftar tenggat terdekat.
   - Batch terbaru per jenis pemindaian dan tren antarsesi.
   - Urutan dibuat deterministik dengan *tie-break* eksplisit.
2. **Repositori:** `history_repo.batch_stats(session, limit)` menghitung statistik per batch: jumlah temuan, rata-rata dan skor tertinggi, jumlah *true positive*, serta jumlah per kelas keparahan.
3. **Endpoint:** `GET /api/v1/dashboard` (hanya baca) dengan parameter `due_soon_days` (1–90).
4. **Antarmuka:** `frontend/components/page_dashboard.py`, halaman **Dasbor** di kelompok "Keputusan", dan kini menjadi halaman pembuka. Prioritas Perbaikan tetap tersedia satu klik di bawahnya.
   - Grafik Plotly memakai tiga slot warna kategorikal tetap (biru, oranye, aqua) yang lolos validasi buta warna. Warna mengikuti entitas: SAST/DAST/Hybrid dan kelompok status selalu memakai warna yang sama.
   - Legenda tampil untuk grafik bertumpuk atau berkelompok, angka ditulis langsung pada bar tunggal, dan setiap grafik memiliki tabel *Lihat data*.
5. **Tes:** `tests/test_dashboard.py`. Empat tes mencakup angka kunci, urutan tenggat, determinisme ranking CWE dan penanggung jawab, batch terbaru, serta endpoint dengan data riwayat.

**Verifikasi:**
- **151 tes lolos**, termasuk uji regresi emas.
- `compileall` dan pyflakes bersih.
- Render halaman pada DB demo dengan `AppTest`: 0 exception, 0 error, 8 metrik, 4 grafik, 5 tabel.
- Tangkapan layar grafik diperiksa untuk label yang terpotong dan urutan seri.

---

## Fase 13 — Perbaikan Bug Hasil Tinjauan DSS (19 November 2026)

**Permintaan:** memeriksa ulang fitur DSS dan memperbaiki bug yang ditemukan.

**Perubahan:**
1. **Form tindak lanjut ditolak untuk peran Pengembang (403).** Widget yang dinonaktifkan tetap mengirim nilai bawaan (dampak bisnis 3, upaya 2), sehingga backend menganggap kolom triase diubah. Akibat lain: analis yang hanya mengubah status ikut menyimpan "Sedang" sebagai pilihan eksplisit.
   - Payload kini disusun oleh `build_decision_payload` di `frontend/components/page_priority.py` dan hanya memuat kolom yang boleh diubah peran pengguna.
   - Pilihan dampak bisnis dan upaya mendapat opsi **"Belum dinilai"** (`None`).
2. **Tenggat SLA tidak mengetat saat rekomendasi naik prioritas.** `upsert_recommendation` hanya mengisi tenggat bila sebelumnya kosong. Kini tenggat otomatis ikut mengetat bila rekomendasi berubah dan tenggat barunya lebih dekat. Tenggat tidak pernah dilonggarkan, dan tidak diubah bila:
   - analis sudah menetapkan prioritas sendiri;
   - isu sudah ditutup;
   - tenggat pernah diubah langsung oleh pengguna (diperiksa dari jejak audit).

   Perubahan tenggat dicatat sebagai peristiwa `RECOMMENDED`.
3. **Simulasi what-if dapat tersimpan sebagai rekomendasi resmi.** `POST /api/v1/dss/rank` dengan `persist=true` kini menolak (422) permintaan yang membawa `weights`, `escalation_rate`, atau `method` berbeda dari konfigurasi. Kebijakan permanen tetap diubah melalui `PUT /config` atau AHP.
4. **Label "dampak bisnis belum dinilai" keliru untuk nilai dari aturan konfigurasi.** Label ini kini mengikuti penanda imputasi `config_default` pada matriks, bukan hanya isian analis. Bug ini laten karena `asset_criticality.rules` masih kosong.
5. **Tes:** enam tes baru di `tests/test_dss_api.py`. `test_rerank_never_overwrites_analyst_decision` tidak lagi menyimpan run dengan metode SAW karena hal itu kini termasuk what-if.

**Verifikasi:** 153 tes lolos. Empat tes regresi emas gagal sejak **sebelum** perubahan ini karena artefak model lokal dan `excluded_domains.json` (tambahan `bunny.net`) berbeda dari baseline v1. Kegagalan ini tidak disebabkan kode DSS, dan penyelesaiannya adalah keputusan pemilik penelitian.

**Belum ditangani (catatan metodologis):**
- Porsi kontribusi kriteria pada metode WP mencampur skala nilai mentah.
- Sensitivitas mengukur urutan MCDM murni, bukan urutan akhir P1–P4.
- Definisi tingkat kesesuaian menghitung perubahan status saja sebagai "sesuai rekomendasi".

---

## Fase 14 — Kunci Data Tersimpan Seluruhnya Berbahasa Inggris (19 November 2026)

**Permintaan:** menghapus sisa kunci berbahasa Indonesia (misalnya `perlu_dicek`) agar penamaan seragam.

**Perubahan:**
1. **Migrasi data** `backend/db/migrations/versions/0004_english_payload_keys.py` menulis ulang JSON tersimpan:
   - `dss_decision_events.payload_json`: `konteks_model` → `model_context` beserta kunci di dalamnya (`asal_skor`, `alasan_model`, `perlu_dicek`, `prioritas_rekomendasi`), dan diff `dari`/`menjadi` → `from`/`to`;
   - `dss_runs.result_json`: kode imputasi lama pada `items[].imputed`.

   Revisi ini idempoten dan tidak mengubah skema.
2. **Kode:** penerjemah kunci lama di `backend/repositories/dss.py` dihapus.
3. **Tes:** tes normalisasi saat baca diganti dua tes migrasi: fungsi normalisasi (termasuk idempotensi) dan penulisan ulang baris nyata lewat `stamp 0003` → `upgrade head`. Tes revisi *head* di `test_database.py` diperbarui.

**Data riset:** sebelum migrasi, `database/database.db` tidak memuat kunci lama (0 dari 8 peristiwa audit, 0 dari 1 run), sehingga tidak ada baris yang berubah. Cadangan dibuat lebih dulu: `database/backups/database-auto-20261119-171529.db`.

**Verifikasi:** 154 tes lolos. Empat tes regresi emas masih gagal karena artefak model lokal, sama seperti sebelum fase ini.

---

## Fase 15 — Penghapusan Caddy (19 November 2026)

**Permintaan:** menghapus penggunaan Caddy.

**Perubahan:**
1. `deploy/Caddyfile` dihapus. Di `docker-compose.yml`, layanan `caddy` beserta volume `caddy_data`/`caddy_config` juga dihapus.
   - `api` dan `ui` kini membuka port 8000 dan 8501 langsung ke host.
   - `uvicorn` tidak lagi memakai `--proxy-headers --forwarded-allow-ips "*"`. Tanpa *proxy* tepercaya di depannya, opsi itu membuat header `X-Forwarded-*` dari klien mana pun ikut dipercaya.
2. `PUBLIC_API_BASE_URL` kini menunjuk ke alamat API yang dapat dijangkau browser; bawaan di Compose adalah `http://localhost:8000`.
   - Di `frontend/utils/config.py`, nilai kosong kini kembali ke `API_BASE_URL`. Sebelumnya nilai kosong menghasilkan tautan relatif yang hanya berfungsi di balik Caddy, sehingga tombol unduh laporan sampel rusak pada instalasi lokal yang mengikuti `.env.sample`.
3. `HAST_DOMAIN` dihapus dari `.env.sample` dan dokumentasi (README, ARCHITECTURE, CONFIGURATION, docs/README).

**Konsekuensi:**
- Tidak ada lagi HTTPS otomatis maupun header keamanan HSTS/nosniff dari Caddy. Bila aplikasi dibuka ke internet, letakkan di balik *reverse proxy*/TLS milik server.
- Unit systemd tetap mengikat `127.0.0.1`, sehingga di server hanya dapat dijangkau secara lokal atau melalui *proxy* lain.

---

## Fase 16 — Pencatatan Issue Otomatis setelah Korelasi Hybrid (19 November 2026)

**Permintaan:** issue langsung tercatat begitu Korelasi Hybrid selesai, tanpa perlu membuka halaman Prioritas Perbaikan.

**Latar belakang:** Dashboard membaca `dss_decisions`, yang sebelumnya baru terisi ketika Prioritas Perbaikan dibuka dalam keadaan login. Akibatnya, korelasi yang dijalankan tanpa membuka halaman itu tampil sebagai 0 issue.

**Perubahan:**
1. `POST /api/v1/correlation/run` menerima pengguna opsional (`get_optional_user`). Bila pengguna memiliki hak `dss.save_run`, endpoint memanggil `dss.service.rank_batch(..., persist=True, actor=...)` untuk sesi baru di dalam *savepoint*.
   - Kegagalan DSS tidak membatalkan hasil korelasi.
   - Respons memuat objek `dss` beserta alasan bila issue tidak tercatat.
2. Pengguna anonim tetap dapat menjalankan korelasi; issue-nya dicatat kemudian lewat Prioritas Perbaikan, seperti sebelumnya.
3. Tab Korelasi Hybrid menampilkan status pencatatan. Dashboard memberi peringatan bila hasil Hybrid ada tetapi belum ada issue tercatat.
4. Tes: tiga tes endpoint (login berhak, tanpa login, role tanpa hak) memakai skoring hybrid sintetis.

**Catatan:** ID sesi berformat `HAST-<detik unix>` (sejak v1), sehingga dua korelasi dalam detik yang sama mendapat ID yang sama dan barisnya tergabung. Kondisi ini muncul saat tes berjalan cepat; dalam pemakaian nyata kecil kemungkinannya. Format ID tidak diubah.

---

## Fase 17 — Deployment di Balik Nginx Proxy Manager (19 November 2026)

**Permintaan:** server produksi memakai Nginx Proxy Manager (NPM).

**Perubahan:**
1. `docker-compose.yml`: `api` dan `ui` tidak lagi membuka port ke host.
   - Keduanya bergabung ke jaringan Docker eksternal `${PROXY_NETWORK:-proxy}` yang juga tersambung ke container NPM, dengan alias unik `hast-api` dan `hast-ui`.
   - Komunikasi internal UI → API tetap memakai jaringan bawaan Compose (`http://api:8000`).
2. README (bagian *Deployment*) memuat langkah:
   - membuat jaringan bersama dan menyambungkan container NPM;
   - mengisi `.env` dengan `PUBLIC_API_BASE_URL=https://<domain>`;
   - mengatur *Proxy Host* NPM: `hast-ui:8501` dengan *Websockets Support* (wajib untuk Streamlit), *custom location* `/api` dan `/sample-reports` → `hast-api:8000`, serta SSL Let's Encrypt dengan Force SSL dan HSTS.
3. `PROXY_NETWORK` ditambahkan ke `.env.sample` dan `docs/CONFIGURATION.md`; baris deployment di `docs/ARCHITECTURE.md` diperbarui.

**Belum diverifikasi:** Docker dan NPM tidak tersedia di mesin pengembangan, sehingga konfigurasi ini perlu dicoba di server.

---

## Fase 18 — Konteks Model pada Rekomendasi Sistem (19 November 2026)

**Permintaan:** kolom "Konteks model saat itu" juga terisi pada baris "Rekomendasi sistem", yaitu penjelasan model saat sistem pertama kali memberi rekomendasi.

**Perubahan:**
1. `backend/repositories/dss.py`: `upsert_recommendation` menyusun payload lewat `_recommendation_payload`, yang menambahkan `model_context` (asal skor, alasan model SHAP, catatan "Perlu diperiksa", prioritas rekomendasi, dan `run_id`). Snapshot ini dibuat saat issue pertama kali dicatat dan setiap kali rekomendasinya berubah.
2. Revisi Alembic `0005_recommendation_model_context` mengisi ulang peristiwa RECOMMENDED lama dari `dss_runs.result_json` milik run yang menghasilkannya, sehingga isinya sama dengan penjelasan pada saat itu.
   - Revisi ini idempoten.
   - Peristiwa yang run-nya tidak ditemukan dibiarkan apa adanya.
3. Tes:
   - baris rekomendasi baru memuat konteks yang sama dengan penjelasan issue;
   - migrasi mengisi ulang baris lama dan aman dijalankan dua kali;
   - revisi *head* di `test_database.py` diperbarui.

**Data riset:** setelah cadangan `database/backups/database-auto-20261119-180318.db`, migrasi mengisi 8 dari 8 peristiwa RECOMMENDED.

**Verifikasi:** 159 tes lolos. Empat tes regresi emas masih gagal karena artefak model lokal, sama seperti sebelumnya.

---

## Dokumentasi yang Diperbarui
- `README.md`: ditulis ulang untuk v2 (fitur DSS, arsitektur singkat, instalasi `uv`, Docker, pengujian).
- `docs/ARCHITECTURE.md`: ditulis ulang (prinsip, pemetaan subsistem DSS, struktur, endpoint, alur DSS, kriteria, halaman, model data, deployment, pengujian).
- `docs/CONFIGURATION.md`: ditambah bagian variabel lingkungan dan `dss_config.json`, serta catatan rumus eskalasi pada bagian `ai_config.json`. Isi lama tidak dihapus.
- `backend/README.md`, `frontend/README.md`, `database/README.md`, `tests/README.md`: disesuaikan dengan struktur v2.
- `CHANGELOG.md`: entri `[2.0.0] - Unreleased`.
- Skill `.claude/skills/hast-dss/`: `references/codebase-map.md` ditulis ulang untuk v2; alur implementasi dan verifikasi di `SKILL.md` diperbarui; status peta jalan ditambahkan di `references/dss-blueprint.md`.

---

## Keputusan Terbuka

Keputusan berikut adalah milik pemilik penelitian. Selama perombakan, **tidak ada satu pun yang diselesaikan secara sepihak**.

| ID | Persoalan | Kondisi saat ini | Yang perlu diputuskan |
| :--- | :--- | :--- | :--- |
| K1 | Rumus eskalasi: engine `base + (10 − base) × ER` vs tes/dokumen `base × (1 + ER)` | Engine dipertahankan (dikunci baseline emas); tes v1 dan dokumen tidak diubah | Rumus mana yang dipakai di naskah; setelah itu selaraskan kode, tes, dan dokumen |
| K2 | Kelas keparahan backend vs frontend berbeda untuk 0 < skor < 0.1 | Keduanya tidak diubah; DSS memakai label backend | Satukan ambang ke satu sumber |
| K3 | Tiga set metrik model berbeda (*seed* `bootstrap.py`, isi `database.db` 2026-10-13, `model_training_result.json` 2026-10-15) | *Seed* v1 dipertahankan apa adanya | Angka mana yang sah untuk naskah; apakah *seed* bawaan dihapus atau diganti dengan pembacaan JSON hasil pelatihan; apakah pipeline dijalankan ulang agar DB sinkron |
| K4 | Rujukan SUS: "Brooke (1986)" di kode/UI vs "Brooke (1996)" di dokumen | Tidak diubah | Verifikasi rujukan yang benar |
| K5 | `tools/benchmark_latency/app.py` (Listing 4.5) memakai `localhost`; di Windows ada jeda ~2 detik per permintaan | Tidak diubah | Periksa apakah angka latensi di naskah diukur di Windows dengan `localhost`; bila ya, ukur ulang dengan `127.0.0.1` |
| K6 | Bobot urutan dan SLA di `dss_config.sample.json` adalah **nilai awal** | Diberi label tegas; pola path aset dihapus (v2.1); SLA awal 7/30/90 hari | Tetapkan bobot via AHP pakar (simpan sumbernya) dan kebijakan SLA organisasi |
| K9 | Satuan alternatif DSS diubah dari **pasangan SAST–DAST** menjadi **isu** (alert ZAP + CWE), dan prioritas P1–P4 kini ditentukan aturan, dengan MCDM hanya mengurutkan di dalam prioritas (v2.1) | Diterapkan atas permintaan pengguna agar DSS praktis; tercatat pada setiap run (`unit: "issue"`) | Sesuaikan bab metodologi: definisi alternatif, peran MCDM, dan instrumen evaluasi pakar (pakar menilai urutan isu, bukan pasangan) |
| K7 | Tumpang tindih C1 (skor model) dengan C3/C4 (metrik CVSS) | Peringatan otomatis di setiap ranking | Kurangi bobot, nonaktifkan C3/C4, atau bahas sebagai keterbatasan |
| K8 | Penerapan ke produksi | Belum ada yang di-commit/push. Tag `v1.0.0-tesis` hanya lokal. Folder `.claude/` (skill) akan ikut ter-commit. | (a) Commit per fase atau sekaligus; (b) push tag; (c) saat backend v2 pertama kali dijalankan pada server, `database.db` produksi dimigrasikan di tempat (revisi 0001–0004: 0001–0003 hanya menambah kolom/tabel, 0004 menulis ulang kunci JSON lama ke bahasa Inggris; cadangan sudah ada di `database/backups/2026-11-17-baseline/`); (d) uji Docker di staging |

Pekerjaan riset lanjutan yang belum dapat dilakukan karena memerlukan data dari manusia:
- mengumpulkan ranking pakar (≥ 2 pakar) untuk evaluasi;
- menyusun penilaian AHP;
- menjalankan putaran SUS v2;
- mencatat keputusan analis yang sungguhan (untuk rasio persetujuan).

---

## Ringkasan Berkas

- **Baru:**
  - `backend/{main.py, core/, db/, repositories/, routers/, services/, dss/}`, `backend/config/dss_config.sample.json`;
  - `frontend/components/{auth_panel, page_decision_log, page_dss_recommendation, page_dss_research, page_dss_weights, page_users}.py`;
  - `tests/{test_dss_core, test_dss_api, test_regression_golden, test_ops_tools}.py`, `tests/golden/`;
  - `tools/{regression, dss_evaluation, backup_db}/`, `tools/benchmark_latency/dss_rank.py`;
  - `pyproject.toml`, `uv.lock`, `alembic.ini`, `Dockerfile`, `.dockerignore`, `docker-compose.yml`, `deploy/`, `.gitea/workflows/`, `.env.sample`;
  - `docs/CATATAN_PERUBAHAN_DSS.md`, skill `.claude/skills/hast-dss/`.
- **Diubah:** seluruh komponen frontend yang sebelumnya mengakses DB/backend, `frontend/app.py`, `frontend/utils/{api_client, config}.py`, `backend/{api, config, model_loader}.py`, `ai-model/training/train_production_model.py`, `tools/convert_sonar_to_cwe/app.py`, tes v1 (impor/fixture saja), `pytest.ini`, `requirements.txt`, `app.sh.sample`, `.gitignore`, serta seluruh dokumen.
- **Dipindah:** `frontend/utils/sonar_cwe_mapper.py` → `backend/services/parsers/sonar_cwe_mapper.py`.
- **Dihapus:** `frontend/utils/database.py`.
- **Tidak disentuh (sengaja):**
  - `backend/engine.py`, pipeline `ai-model/` (kecuali penulisan metrik);
  - `ai-model/data/*_result.json`, `tests/test_formatters_and_hast.py`, `tools/benchmark_latency/app.py`;
  - `database/database.db` (hanya disalin; migrasi diuji pada salinan);
  - `app.sh` lokal.
- **Lingkungan:** `.venv` lama yang rusak diganti nama menjadi `.venv-broken-py313/` (dapat dihapus bila tidak diperlukan); `.venv` baru dibuat oleh `uv sync`.

## Cara Kembali ke v1
```bash
git stash -u            # atau commit perubahan v2 ke cabang terpisah
git checkout v1.0.0-tesis
cp database/backups/2026-11-17-baseline/database.db database/database.db   # bila DB sudah dimigrasikan v2
```
