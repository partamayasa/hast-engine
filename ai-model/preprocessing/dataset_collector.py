import json
import csv
from datetime import datetime
from pathlib import Path

# Ambil lokasi absolut direktori 'ai-model/preprocessing'
BASE_DIR = Path(__file__).resolve().parent

# Naik ke 'ai-model' lalu masuk ke direktori 'data'
DATA_DIR = BASE_DIR.parent / "data"

# Buat direktori 'ai-model/data' secara otomatis bila belum ada
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Atur jalur absolut berkas masukan dan keluaran secara dinamis
json_files = sorted(DATA_DIR.glob('nvdcve/nvdcve-2.0-*.json'))
output_csv = DATA_DIR / 'cve_cvss4_dataset.csv'


def format_date(date_str):
    # Konversi format tanggal ISO dari JSON NVD ke format lokal
    if not date_str:
        return ""
    dt = datetime.strptime(date_str.split('.')[0], "%Y-%m-%dT%H:%M:%S")
    return dt.strftime("%d-%m-%Y %H:%M")


# Atur urutan kolom untuk struktur CSV dataset
headers = [
    "cve_id", "mod_date", "pub_date", "cvss_score", "cvss_severity", "cwe_code", "summary",
    "attack_vector", "attack_complexity", "attack_requirements", "privileges_required", "user_interaction",
    "vuln_confidentiality", "vuln_integrity", "vuln_availability",
    "sub_confidentiality", "sub_integrity", "sub_availability"
]

total_saved = 0

print("----------------------------------")
print("Memulai Ekstraksi Dataset CVSS 4.0")
print("----------------------------------")
print(f"Target folder data: {DATA_DIR}")

# Buka berkas CSV keluaran untuk menulis record hasil ekstraksi
with open(output_csv, mode='w', encoding='utf-8', newline='') as f_csv:
    writer = csv.writer(f_csv)
    writer.writerow(headers)

    # Iterasi untuk mengurai berkas JSON NVD tahunan secara berurutan
    for file_path in json_files:
        file_name = file_path.name
        if not file_path.exists():
            print(f"[Lewat]: Berkas {file_name} tidak ditemukan di folder data. Melanjutkan")
            continue

        try:
            print(f"-> Sedang memproses: {file_name}")
            with open(file_path, 'r', encoding='utf-8') as f_json:
                data = json.load(f_json)

                # Iterasi atas objek kerentanan dalam struktur data JSON utama
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    metrics = cve.get('metrics', {})

                    # Filter: hanya proses record yang memiliki parameter cvssMetricV40
                    if not metrics.get('cvssMetricV40'):
                        continue

                    cvss_item = metrics['cvssMetricV40'][0].get('cvssData', {})

                    # Ekstrak metadata umum dan pengenal CVE
                    cve_id = cve.get('id')
                    mod_date = format_date(cve.get('lastModified'))
                    pub_date = format_date(cve.get('published'))
                    summary = next((d.get('value') for d in cve.get('descriptions', []) if d.get('lang') == 'en'), "")

                    # Ekstrak CWE ID dari deskripsi berbahasa Inggris
                    cwe_code = ""
                    for weakness in cve.get('weaknesses', []):
                        for desc in weakness.get('description', []):
                            if desc.get('lang') == 'en':
                                cwe_code = desc.get('value')
                                break

                    # Tulis baris baru berisi metrik CVSS v4.0 hasil ekstraksi
                    writer.writerow([
                        cve_id, mod_date, pub_date,
                        cvss_item.get('baseScore', ''),
                        cvss_item.get('baseSeverity', ''),
                        cwe_code, summary,
                        cvss_item.get('attackVector', ''),
                        cvss_item.get('attackComplexity', ''),
                        cvss_item.get('attackRequirements', ''),
                        cvss_item.get('privilegesRequired', ''),
                        cvss_item.get('userInteraction', ''),
                        cvss_item.get('vulnConfidentialityImpact', ''),
                        cvss_item.get('vulnIntegrityImpact', ''),
                        cvss_item.get('vulnAvailabilityImpact', ''),
                        cvss_item.get('subsequentSystemConfidentialityImpact', ''),
                        cvss_item.get('subsequentSystemIntegrityImpact', ''),
                        cvss_item.get('subsequentSystemAvailabilityImpact', '')
                    ])
                    total_saved += 1

        except Exception as e:
            print(f"[Eror]: Gagal membaca berkas {file_name}. Alasan: {str(e)}")

print("Proses selesai!. Berkas dataset disimpan")
print(f"-> Berhasil mengumpulkan {total_saved} data CVSS 4.0")
print("--------------------------------------------")
