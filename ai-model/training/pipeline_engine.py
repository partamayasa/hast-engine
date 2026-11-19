import subprocess
import os
import sys
import json
import csv
from datetime import datetime
from pathlib import Path

# Atur jalur absolut direktori 'training' agar eksekusi aman dan mandiri
TRAINING_DIR = Path(__file__).resolve().parent

# Naik satu tingkat ke direktori induk 'ai-model' secara lintas platform
AI_MODEL_DIR = TRAINING_DIR.parent


def run_script(script_name, subfolder=None):
    """Fungsi bantu untuk menjalankan skrip Python memakai jalur Pathlib absolut."""
    if subfolder:
        script_path = AI_MODEL_DIR / subfolder / script_name
    else:
        script_path = AI_MODEL_DIR / script_name

    print(f"\n[Pipeline Engine] Menjalankan: {script_path.name}")

    # Konversi jalur menjadi string agar aman dieksekusi oleh subprocess eksternal
    str_script_path = str(script_path.resolve())

    # Jalankan skrip memakai interpreter Python aktif agar konteks virtual environment tetap terjaga
    result = subprocess.run([sys.executable, str_script_path], capture_output=False, text=True)

    # Periksa apakah skrip gagal (kode keluar bukan nol)
    if result.returncode != 0:
        print(f"\n[Error] {script_name} gagal dieksekusi dengan kode keluar: {result.returncode}")
        sys.exit(1)


def update_system_summary():
    """Memperbarui atau menimpa system_summary.json di backend/config/ setelah pipeline selesai."""
    root_dir = AI_MODEL_DIR.parent
    summary_path = root_dir / "backend" / "config" / "system_summary.json"
    ai_config_path = AI_MODEL_DIR / "config" / "ai_config.json"
    app_config_path = root_dir / "frontend" / "config" / "app_config.json"
    cwe_lookup_path = AI_MODEL_DIR / "data" / "cwe_cvss4_lookup_table.csv"
    cve_dataset_path = AI_MODEL_DIR / "data" / "cve_cvss4_dataset.csv"

    print("\n[Pipeline Engine] Memperbarui ringkasan sistem (system_summary.json)")

    # Nilai bawaan bila berkas konfigurasi belum ada
    summary_data = {
        "api_title": "N/A",
        "api_description": "N/A",
        "app_version": "N/A",
        "active_model": "N/A",
        "escalation_rate": "N/A",
        "variety_cwe": "N/A",
        "number_cvss4_records": "N/A",
        "dataset_timestamp": "N/A",
        "last_updated": datetime.now().strftime("%Y-%m-%d")
    }

    # Ekstrak konfigurasi dari app_config.json bila tersedia
    if app_config_path.exists():
        try:
            with open(app_config_path, "r", encoding="utf-8") as f:
                app_cfg = json.load(f)
                summary_data["api_title"] = app_cfg.get("api_title", summary_data["api_title"])
                summary_data["api_description"] = app_cfg.get("api_description", summary_data["api_description"])
                summary_data["app_version"] = app_cfg.get("app_version", summary_data["app_version"])
                if "dataset_timestamp" in app_cfg:
                    summary_data["dataset_timestamp"] = app_cfg["dataset_timestamp"]
        except Exception as e:
            print(f"[Warning] Gagal membaca app_config.json: {e}")

    # Ekstrak konfigurasi dari ai_config.json bila tersedia
    if ai_config_path.exists():
        try:
            with open(ai_config_path, "r", encoding="utf-8") as f:
                ai_cfg = json.load(f)
                summary_data["active_model"] = ai_cfg.get("active_model", summary_data["active_model"])
                summary_data["escalation_rate"] = ai_cfg.get("escalation_rate", summary_data["escalation_rate"])
        except Exception as e:
            print(f"[Warning] Gagal membaca ai_config.json: {e}")

    # Deteksi otomatis tanggal snapshot dataset dari berkas JSON nvdcve mentah
    nvd_folder = AI_MODEL_DIR / "data" / "nvdcve"
    detected_ts = None
    if nvd_folder.exists():
        for json_file in sorted(nvd_folder.glob("nvdcve-2.0-*.json"), reverse=True):
            try:
                with open(json_file, "r", encoding="utf-8") as f_nvd:
                    for _ in range(50):
                        line = f_nvd.readline()
                        if not line:
                            break
                        if '"timestamp"' in line:
                            parts = line.split('"timestamp"')
                            if len(parts) > 1 and '"' in parts[1]:
                                raw_val = parts[1].split('"')[1].strip()
                                date_only = raw_val.split("T")[0]
                                if len(date_only) == 10 and date_only.count("-") == 2:
                                    detected_ts = date_only
                                else:
                                    detected_ts = raw_val
                                break
            except Exception as e:
                print(f"[Warning] Gagal membaca timestamp dari {json_file.name}: {e}")
            if detected_ts:
                summary_data["dataset_timestamp"] = detected_ts
                break

    # Sinkronkan dataset_timestamp terbaru ke app_config.json agar frontend tetap selaras
    if detected_ts and app_config_path.exists():
        try:
            with open(app_config_path, "r", encoding="utf-8") as f:
                app_cfg = json.load(f)
            if app_cfg.get("dataset_timestamp") != detected_ts:
                app_cfg["dataset_timestamp"] = detected_ts
                with open(app_config_path, "w", encoding="utf-8") as f:
                    json.dump(app_cfg, f, indent=2, ensure_ascii=False)
                print(f"-> [Sinkron] {app_config_path.name} otomatis diperbarui ke tanggal: {detected_ts}")
        except Exception as e:
            print(f"[Warning] Gagal menyinkronkan {app_config_path.name}: {e}")

    # Hitung jumlah tipe CWE unik dari cwe_cvss4_lookup_table.csv
    if cwe_lookup_path.exists():
        try:
            with open(cwe_lookup_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader, None)  # Lewati header
                summary_data["variety_cwe"] = sum(1 for _ in reader)
        except Exception as e:
            print(f"[Warning] Gagal menghitung variety_cwe dari {cwe_lookup_path.name}: {e}")

    # Hitung total baris dari cve_cvss4_dataset.csv
    if cve_dataset_path.exists():
        try:
            with open(cve_dataset_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader, None)  # Lewati header
                summary_data["number_cvss4_records"] = sum(1 for _ in reader)
        except Exception as e:
            print(f"[Warning] Gagal menghitung number_cvss4_records dari {cve_dataset_path.name}: {e}")

    # Simpan/timpa system_summary.json di backend/config/
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2, ensure_ascii=False)
        print(f"-> [Sukses] {summary_path.name} berhasil diperbarui di: {summary_path.resolve()}")
    except Exception as e:
        print(f"[Error] Gagal menulis ke {summary_path.name}: {e}")


if __name__ == "__main__":
    print("-----------------------------------------------------------------------")
    print("Inisialisasi Cybersecurity Vulnerability Quantification Pipeline Engine")
    print("-----------------------------------------------------------------------")
    print(f"Direktori kerja AI model: {AI_MODEL_DIR.resolve()}")

    # Tahap 1: Ekstrak data JSON NVD mentah ke cve_cvss4_dataset.csv
    run_script("dataset_collector.py", subfolder="preprocessing")

    # Tahap 2: Bangun tabel rujukan lookup ke cwe_cvss4_lookup_table.csv
    run_script("cwe_profiler.py", subfolder="preprocessing")

    # Tahap 3: Latih model machine learning dan lakukan evaluasi internal
    run_script("train_production_model.py", subfolder="training")

    # Tahap 4: Perbarui manifest ringkasan sistem (system_summary.json)
    update_system_summary()

    print("------------------------------------------------------------------------------")
    print("[Sukses] Seluruh tahapan pipeline dan pelatihan model selesai dieksekusi!")
    print("------------------------------------------------------------------------------")
