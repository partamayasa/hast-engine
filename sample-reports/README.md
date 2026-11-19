# Sample Reports: Berkas Sampel Hasil Pemindaian SAST dan DAST

Direktori `sample-reports/` menyediakan berkas sampel laporan pengujian keamanan perangkat lunak terstandardisasi yang dihasilkan oleh alat pemindai keamanan kode statis (**SonarQube SAST**) dan pemindai keamanan aplikasi dinamis (**OWASP ZAP DAST**). Berkas-berkas ini digunakan sebagai data uji acuan (*benchmark sample data*) untuk menguji fungsi penguraian (*parsing*), kuantifikasi keparahan kerentanan, dan korelasi hibrida pada tahap replikasi penelitian.

---

## 1. Struktur Direktori dan Berkas

```text
sample-reports/
├── .gitkeep                 # Berkas penanda pelacakan direktori di dalam Git
├── OWASP_ZAP_Report.json    # Sampel berkas JSON laporan pengujian penetrasi aktif OWASP ZAP (DAST)
└── SonarQube_Report.json    # Sampel berkas JSON laporan analisis kode statis SonarQube (SAST)
```

---

## 2. Deskripsi dan Spesifikasi Berkas Sampel

### A. `SonarQube_Report.json` (Static Application Security Testing - SAST)
- **Asal Alat**: SonarQube Community Edition / Server API.
- **Karakteristik Data**: Analisis berbasis kode sumber internal aplikasi web (`app.example.com`).
- **Elemen Kunci**:
  - `metadata`: Informasi proyek, jumlah temuan total (`totalIssues`), dan waktu pemindaian.
  - `issues`: Daftar temuan keamanan, mencakup kunci unik issue (`key`), kode aturan SonarQube (`rule`, misal `php:S1192`), tingkat keparahan asli scanner (`severity`), path berkas kode (`component`), nomor baris kode terdampak (`line`), serta pesan ringkasan (`message`).
- **Peran dalam Penelitian**: Menjadi masukan utama (*Left-Base*) pada pipeline korelasi kerentanan hibrida untuk mendeteksi potensi cacat perangkat lunak pada tingkat baris kode.

### B. `OWASP_ZAP_Report.json` (Dynamic Application Security Testing - DAST)
- **Asal Alat**: OWASP Zed Attack Proxy (ZAP) versi 2.17.0.
- **Karakteristik Data**: Pemindaian dinamis berbasis perilaku aplikasi web saat berjalan (*live runtime blackbox test*) terhadap target `https://app.example.com`.
- **Elemen Kunci**:
  - `site`: URL basis target pengujian.
  - `alerts`: Daftar temuan kerentanan runtime, mencakup nama alert (`alert`), pengenal CWE (`cweid`), pengenal WASC (`wascid`), tingkat risiko (`riskcode`, `riskdesc`), parameter yang rentan (`param`), bukti respons payload (`evidence`), serta URL endpoint terdampak.
- **Peran dalam Penelitian**: Menjadi data pembanding silang untuk memvalidasi apakah temuan kelemahan kode statis (SAST) benar-benar dapat dieksploitasi dari luar pada lapisan jaringan/aplikasi (DAST). Jika CWE ID temuan cocok, sistem menetapkan status *True Positive* dan memberlakukan eskalasi skor risiko.

---

## 3. Cara Penggunaan untuk Replikasi Penelitian

Berkas-berkas sampel ini dapat dimanfaatkan dalam 2 cara:

### Cara 1: Unggah Langsung Melalui Antarmuka Dashboard Streamlit
1. Buka dashboard di peramban web (`http://localhost:8501`).
2. Masuk ke **Tab 1 (SAST Analysis)**: unggah berkas `sample-reports/SonarQube_Report.json`.
3. Masuk ke **Tab 2 (DAST Analysis)**: unggah berkas `sample-reports/OWASP_ZAP_Report.json`.
4. Masuk ke **Tab 3 (Hybrid Correlation)**: lakukan korelasi otomatis untuk mengamati pencocokan CWE, perhitungan eskalasi risiko, dan pemfilteran temuan *false positive*.

### Cara 2: Akses Melalui Endpoint REST API Backend
Backend API menyediakan rute bawaan untuk mengunduh berkas sampel ini secara terprogram:
```bash
# Mengunduh sampel laporan SonarQube via API
curl -O http://127.0.0.1:8000/sample-reports/SonarQube_Report.json

# Mengunduh sampel laporan OWASP ZAP via API
curl -O http://127.0.0.1:8000/sample-reports/OWASP_ZAP_Report.json
```

