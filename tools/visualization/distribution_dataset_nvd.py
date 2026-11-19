# tools/visualization/distribution_dataset_nvd.py
import os
import time
import pandas as pd
import matplotlib.pyplot as plt

# Tentukan jalur direktori kerja secara absolut dan dinamis
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
DATASET_PATH = os.path.join(ROOT_DIR, "ai-model", "data", "cve_cvss4_dataset.csv")
OUTPUT_DIR = os.path.join(ROOT_DIR, "tools", "data")

def main():
    print("----------------------------------------------------------------")
    print("Memulai Analisis Statistik & Visualisasi Dataset NVD (CVSS v4.0)")
    print("----------------------------------------------------------------")
    print(f"Jalur berkas dataset: {DATASET_PATH}")
    
    if not os.path.exists(DATASET_PATH):
        print(f"[Error]: Berkas dataset tidak ditemukan di '{DATASET_PATH}'!")
        return

    try:
        # Memuat berkas dataset
        dataframe = pd.read_csv(DATASET_PATH)
        print(f"-> Sukses memuat dataset. Total baris mentah: {len(dataframe):,} baris.")
        
        if 'cvss_severity' not in dataframe.columns:
            print("[Error]: Kolom 'cvss_severity' tidak ditemukan dalam dataset!")
            return
            
        # Bersihkan nilai severity ke uppercase dan hapus baris kosong
        cleaned_dataframe = dataframe.dropna(subset=['cvss_severity']).copy()
        cleaned_dataframe['cvss_severity'] = cleaned_dataframe['cvss_severity'].astype(str).str.upper()
        total_valid = len(cleaned_dataframe)
        print(f"-> Total data valid (non-null severity): {total_valid:,} baris.\n")
        
        # Hitung distribusi frekuensi
        severity_counts = cleaned_dataframe['cvss_severity'].value_counts()
        
        # Tentukan urutan kategori yang logis
        severity_order = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
        # Susun statistik data untuk dicetak dan divisualisasikan
        statistics_list = []
        for severity in severity_order:
            count = severity_counts.get(severity, 0)
            percentage = (count / total_valid * 100) if total_valid > 0 else 0.0
            statistics_list.append({
                "Tingkat Keparahan": severity,
                "Jumlah": count,
                "Persentase (%)": percentage
            })
            
        statistics_dataframe = pd.DataFrame(statistics_list)
        
        # Cetak tabel statistik ke terminal
        print("-" * 65)
        print(f"{'Kategori Severity':<20} | {'Jumlah Kasus (Count)':<20} | {'Persentase (%)':<15}")
        print("-" * 65)
        for _, row in statistics_dataframe.iterrows():
            print(f"{row['Tingkat Keparahan']:<20} | {int(row['Jumlah']):<20,} | {row['Persentase (%)']:<14.2f}%")
        print("-" * 65)
        
        # Konfigurasi gaya visualisasi bersih
        plt.style.use('default')
        fig, ax = plt.subplots(figsize=(10, 6.5), dpi=600)
        
        # Skema warna yang representatif dan kontras
        color_palette = {
            "NONE": "#b0bec5",      # Abu-abu sejuk
            "LOW": "#42a5f5",       # Biru
            "MEDIUM": "#ffb74d",    # Kuning hangat
            "HIGH": "#ff7043",      # Oranye tua
            "CRITICAL": "#d32f2f"   # Merah cerah
        }
        colors = [color_palette[severity] for severity in statistics_dataframe["Tingkat Keparahan"]]
        
        # Gambar diagram batang
        bars = ax.bar(
            statistics_dataframe["Tingkat Keparahan"], 
            statistics_dataframe["Jumlah"], 
            color=colors, 
            edgecolor='white', 
            linewidth=1.2,
            width=0.6,
            alpha=0.9
        )
        
        # Atur label dan estetika grafik
        ax.set_title("Distribusi Tingkat Keparahan (Severity) CVSS v4.0 pada Dataset NVD", fontsize=14, fontweight='normal', pad=20, color='black')
        ax.set_xlabel("Tingkat Keparahan", fontsize=11, fontweight='normal', labelpad=10, color='black')
        ax.set_ylabel("Jumlah Kerentanan", fontsize=11, fontweight='normal', labelpad=10, color='black')
        
        # Atur batas dan grid (hanya garis horizontal putus-putus yang samar)
        ax.grid(False)
        ax.grid(axis='y', visible=True, linestyle='--', alpha=0.2, linewidth=0.5)
        ax.set_axisbelow(True)
        
        # Set warna tulisan sumbu (ticks) menjadi hitam
        ax.tick_params(axis='both', colors='black')
        
        # Hilangkan garis tepi atas dan kanan agar terlihat bersih
        for spine in ['top', 'right']:
            ax.spines[spine].set_visible(False)
            
        # Format angka sumbu Y agar menggunakan pemisah ribuan
        ax.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda x, loc: f"{int(x):,}"))
        
        # Tambahkan label teks persentase dan jumlah di atas setiap diagram batang
        for bar, row in zip(bars, statistics_list):
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                height + (total_valid * 0.015), # Margin vertikal sedikit di atas batang
                f"{row['Jumlah']:,}\n({row['Persentase (%)']:.2f}%)",
                ha='center',
                va='bottom',
                fontsize=10,
                fontweight='normal',
                color='black'
            )
            
        # Berikan padding tambahan di sumbu Y agar label teks di atas batang tertinggi tidak terpotong
        ax.set_ylim(0, max(statistics_dataframe["Jumlah"]) * 1.15)
        
        # Simpan diagram ke folder tools/data
        unix_time = int(time.time())
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        filename = f"{unix_time}_cve_cvss4_severity_distribution.png"
        output_path = os.path.join(OUTPUT_DIR, filename)
        
        plt.tight_layout()
        plt.savefig(output_path, format='png', bbox_inches='tight', dpi=600)
        plt.close()
        
        print(f"\n[Sukses]: Diagram batang visualisasi berhasil disimpan di:")
        print(f"-> {output_path}")
        print("----------------------------------------------------------------")
        
    except Exception as e:
        print(f"[Error]: Terjadi anomali saat memproses statistik: {e}")

if __name__ == "__main__":
    main()
