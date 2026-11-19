#!/usr/bin/env python3
"""
tools/convert_sonar_to_cwe/app.py

Alat konversi & pengayaan laporan SonarQube ke CWE-ID melalui SonarQube Web API & cache dinamis.
Padanan lintas platform sekaligus pengganti convert-sonar-to-cwe.ps1 dan sonar_rules_cwe.json.

Pemakaian:
    python tools/convert_sonar_to_cwe/app.py -i scan-cli-sonar-report.json
    python tools/convert_sonar_to_cwe/app.py -i input.json -o output-with-cwe.json --token <TOKEN>
"""

import os
import sys
import json
import argparse

# Tambahkan akar proyek ke sys.path secara dinamis
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
curr = SCRIPT_DIR
while curr and not os.path.exists(os.path.join(curr, "requirements.txt")):
    parent = os.path.dirname(curr)
    if parent == curr:
        break
    curr = parent
ROOT_DIR = curr
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.services.parsers.sonar_cwe_mapper import DEFAULT_SONAR_HOST, get_sonar_config
from backend.services.parsers.sonar_cwe_mapper import convert_sonar_report


def main():
    env_host, env_token = get_sonar_config()
    parser = argparse.ArgumentParser(
        description="Konversi & Pengayaan Laporan SonarQube ke CWE-ID via SonarQube Web API."
    )
    parser.add_argument("-i", "--input", dest="input_file", help="Path berkas laporan SonarQube JSON.")
    parser.add_argument("-o", "--output", dest="output_file", help="Path berkas output JSON yang diperkaya.")
    parser.add_argument("-t", "--token", dest="token", default=env_token, help="SonarQube User Token (default dimuat dari .env).")
    parser.add_argument("--host", dest="sonar_host", default=env_host, help=f"SonarQube Host URL (default dari .env: {env_host}).")

    args = parser.parse_args()

    input_file = args.input_file
    if input_file:
        input_file = os.path.normpath(input_file)
        if not os.path.exists(input_file):
            alt = os.path.normpath(os.path.join(ROOT_DIR, input_file))
            if os.path.exists(alt):
                input_file = alt
    else:
        # Prioritas pencarian otomatis
        candidates = [
            os.path.join(ROOT_DIR, "sample-reports", "SonarQube_Report.json"),
        ]
        for c in candidates:
            if os.path.exists(c):
                input_file = c
                break

    if not input_file or not os.path.exists(input_file):
        print(f"[Error] Berkas input tidak ditemukan: {input_file or 'Tidak ada berkas yang ditentukan'}", file=sys.stderr)
        sys.exit(1)

    input_file = os.path.abspath(input_file)
    output_file = args.output_file
    if not output_file:
        dir_name = os.path.dirname(input_file)
        base_name, _ = os.path.splitext(os.path.basename(input_file))
        output_file = os.path.join(dir_name, f"{base_name}-with-cwe.json")
    else:
        output_file = os.path.abspath(output_file)

    print("==================================================================")
    print("     KONVERSI TEMUAN SONARQUBE KE CWE-ID VIA SONARQUBE API       ")
    print("==================================================================")
    print(f" Input File : {os.path.basename(input_file)}")
    print(f" Output File: {os.path.basename(output_file)}")
    print(f" Sonar Host : {args.sonar_host}")
    print("==================================================================\n")

    print("-> Membaca berkas JSON")
    try:
        with open(input_file, "r", encoding="utf-8-sig") as f:
            report_data = json.load(f)
    except Exception as e:
        print(f"[Error] Gagal membaca {input_file}: {e}", file=sys.stderr)
        sys.exit(1)

    issues = report_data.get("issues", [])
    if not issues:
        print(f"[Error] Tidak ditemukan array 'issues' pada berkas: {input_file}", file=sys.stderr)
        sys.exit(1)

    print(f"   Total issues dalam berkas: {len(issues)}")

    def progress(cur, tot, rule):
        print(f"\r   [{cur}/{tot}] Mengambil metadata aturan: {rule:<35}", end="", flush=True)

    print("-> Mengambil metadata CWE & OWASP dari SonarQube API")
    enriched_data, stats = convert_sonar_report(
        report_data=report_data,
        sonar_host=args.sonar_host,
        token=args.token,
        progress_callback=progress
    )
    print("\n   Selesai mengambil metadata semua aturan unik.\n")

    print(f"-> Menyimpan berkas hasil konversi ke: {output_file}")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(enriched_data, f, indent=2, ensure_ascii=False)
    print("   Berkas berhasil disimpan!\n")

    print("=================== RINGKASAN KONVERSI CWE ===================")
    print(f" Total Issues Diproses       : {stats['total_issues']}")
    print(f" Total Issues Mapped ke CWE  : {stats['cwe_mapped_count']}")
    print(f" Total Unique CWE Ditemukan  : {stats['unique_cwe_count']}")
    print("==============================================================\n")

    print("Distribusi CWE yang Terdeteksi:")
    for cwe_name, count in stats["cwe_distribution"].items():
        print(f"  - {cwe_name:<10} : {count} temuan")

    print("\nDaftar Aturan Keamanan & CWE Mapping dari SonarQube:")
    for rule_key, meta in stats["rule_metadata_map"].items():
        cwes = meta.get("cwe", [])
        if cwes:
            cwe_str = ", ".join(cwes)
            print(f"  [{rule_key}] {meta.get('name', '')}")
            print(f"    -> CWE   : {cwe_str}")
            owasps = meta.get("owasp", [])
            if owasps:
                print(f"    -> OWASP : {'; '.join(owasps)}")

    print(f"\n[SELESAI] Hasil konversi tersimpan di: {output_file}")


if __name__ == "__main__":
    main()
