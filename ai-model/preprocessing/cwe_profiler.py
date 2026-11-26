import pandas as pd
import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "data"))

input_csv_path = os.path.join(DATA_DIR, 'cve_cvss4_dataset.csv')
output_csv_path = os.path.join(DATA_DIR, 'cwe_cvss4_lookup_table.csv')
config_json_path = os.path.abspath(os.path.join(BASE_DIR, "..", "config", "ai_config.json"))

print("-------------------------------------------------")
print("Memulai Pembentukan Profil Standar CWE (CVSS 4.0)")
print("-------------------------------------------------")

if not os.path.exists(input_csv_path):
    print(f"[Eror Critical]: Berkas dataset hulu tidak ditemukan di: {input_csv_path}")
    exit()

# 1. Baca skema aktif dari ai_config.json (bawaan: CVSSv4)
severity_scheme = "CVSSv4"
if os.path.exists(config_json_path):
    with open(config_json_path, 'r') as f:
        severity_scheme = json.load(f).get("default_severity_scheme", "CVSSv4")

# 2. Muat dataset lalu hitung modus/rata-rata per CWE ID
df = pd.read_csv(input_csv_path).dropna(subset=['cwe_code'])


def get_mode(x):
    return x.mode().iloc[0] if not x.mode().empty else "NONE"


# Saring fitur agar kolom metadata, teks naratif individual, dan kunci pengelompokan tidak ikut diagregasi
excluded_cols = {'cwe_code', 'cve_id', 'mod_date', 'pub_date', 'cvss_severity', 'summary'}
target_cols = [col for col in df.columns if col not in excluded_cols]

cwe_profile = df.groupby('cwe_code').agg({
    col: 'mean' if col == 'cvss_score' else get_mode for col in target_cols
}).reset_index()

# 3. Klasifikasi kualitatif memakai skema aktif
if severity_scheme == "CVSSv4":
    # Gunakan pd.cut untuk mengelompokkan rentang skor CVSS v4.0
    cwe_profile.insert(2, 'cwe_severity', pd.cut(
        cwe_profile['cvss_score'],
        bins=[-float('inf'), 0.0, 3.9, 6.9, 8.9, 10.0],
        labels=['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        include_lowest=True
    ).astype(str))

cwe_profile.to_csv(output_csv_path, index=False)
print(f"Proses selesai! Total: {len(cwe_profile)} jenis CWE sukses terpetakan")
print("------------------------------------------------------")
