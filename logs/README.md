# Logs Subsystem: Direktori Pencatatan Aktivitas dan Jejak Eksekusi Runtime

Direktori `logs/` disiapkan sebagai wadah terisolasi untuk menampung seluruh berkas pencatatan aktivitas (*application runtime logs*), jejak eksekusi (*diagnostic execution traces*), dan keluaran proses latar belakang (*background workers*) saat sistem dijalankan pada lingkungan server maupun pengembangan lokal.

---

## 1. Struktur Direktori dan Berkas

```text
logs/
├── .gitkeep                 # Berkas penanda pelacakan direktori di dalam Git
└── *                        # Berkas log runtime (seluruh isi diabaikan Git, kecuali .gitkeep dan README.md)
```

---

## 2. Peran dan Fungsi dalam Replikasi Riset

Dalam konteks replikasi dan auditabilitas penelitian:
1. **Pemisahan Berkas Runtime Dinamis**: Menyediakan lokasi terstandarisasi untuk menangkap aliran keluaran (*standard output* dan *standard error*) dari server Backend API (`uvicorn`) maupun Frontend (`streamlit`) tanpa mencemari direktori kode sumber utama.
2. **Audit Diagnostik dan Debugging**: Memfasilitasi pelacakan anomali inferensi, kesalahan format masukan berkas laporan pengujian keamanan, atau galat komunikasi jaringan antara antarmuka pengguna dan mesin prediksi.
3. **Isolasi Version Control**: Berdasarkan `.gitignore` (`logs/*`), seluruh isi direktori ini dikecualikan dari repositori Git, kecuali `.gitkeep` dan `README.md`. Tujuannya menjaga kerahasiaan jejak server dan mencegah pembengkakan ukuran repositori.
4. **Deployment Docker**: `docker-compose.yml` me-*mount* `./logs` ke `/app/logs` di kontainer, sehingga log tetap berada di host.

---

## 3. Contoh Pengalihan Log Runtime

Saat melakukan deployment pengujian atau otomatisasi batch run di lingkungan server, keluaran proses dapat dialihkan secara langsung ke direktori ini:

```bash
# Mengalihkan log eksekusi Backend API ke berkas backend.log
uv run uvicorn backend.api:app --host 127.0.0.1 --port 8000 > logs/backend.log 2>&1 &

# Mengalihkan log eksekusi Frontend Streamlit ke berkas frontend.log
uv run streamlit run frontend/app.py > logs/frontend.log 2>&1 &
```

Gunakan `--host 0.0.0.0` hanya bila backend memang perlu diakses dari mesin lain. Pada deployment Docker, backend berada di belakang Caddy.

Untuk deployment dengan systemd (`deploy/systemd/`), log dibaca dengan `journalctl -u hast-api` dan `journalctl -u hast-ui`.

