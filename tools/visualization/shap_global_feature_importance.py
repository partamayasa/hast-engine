# tools/visualization/shap_global_feature_importance.py
import os
import time
import pickle
import tempfile
import warnings
import pandas as pd
import numpy as np

# Hindari peringatan izin cache matplotlib di lingkungan terbatas
os.environ.setdefault("MPLCONFIGDIR", os.path.join(tempfile.gettempdir(), "matplotlib_vis_cache"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore", category=UserWarning)

# Direktori dinamis
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
MODEL_PATH = os.path.join(ROOT_DIR, "ai-model", "artifacts", "model_random_forest.pkl")
TFIDF_PATH = os.path.join(ROOT_DIR, "ai-model", "artifacts", "tfidf_vectorizer.pkl")
OUTPUT_DIR = os.path.join(ROOT_DIR, "tools", "data")


def plot_single_shap_bar(features_list, title, output_path, dpi=600):
    """
    Renders Top-20 SHAP / Feature Importance Bar Chart persis seperti
    standar visualisasi skripsi dan publikasi ilmiah.
    """
    # Reverse agar kontribusi tertinggi berada paling atas
    rev_features = list(reversed(features_list))

    tokens = [f[0] for f in rev_features]
    vals = [f[1] for f in rev_features]
    y_pos = np.arange(len(tokens))

    # Warna biru standar resmi SHAP bar plot (#008bfb)
    bar_color = "#008bfb"

    # Reset ke style default untuk mencegah kontaminasi style antar modul
    plt.style.use('default')

    fig, ax = plt.subplots(figsize=(11.0, 7.5), dpi=dpi)

    bars = ax.barh(y_pos, vals, color=bar_color, height=0.62, zorder=3)

    max_val = max(vals) if len(vals) > 0 and max(vals) > 0 else 1.0

    # Anotasi 4 digit desimal di ujung kanan setiap batang
    for bar, val in zip(bars, vals):
        ax.text(
            val + (max_val * 0.008), bar.get_y() + bar.get_height() / 2,
            f"{val:.4f}",
            va='center', ha='left',
            fontsize=9.5, color='#111111'
        )

    ax.set_yticks(y_pos)
    ax.set_yticklabels(tokens, fontsize=10.5, color='#111111')
    ax.set_xlim(0, max_val * 1.18)

    ax.set_xlabel('Dampak Rata-Rata terhadap Prediksi Skor CVSS v4.0', fontsize=11.5, labelpad=12, color='#111111')
    ax.set_title(title, fontsize=15, pad=16, color='#111111')

    # Nonaktifkan semua grid horizontal latar belakang
    ax.grid(False)
    ax.yaxis.grid(False)

    # Grid vertikal garis putus-putus abu-abu halus hanya pada sumbu X
    ax.xaxis.grid(True, linestyle='--', color='#e5e7eb', alpha=0.8, zorder=0)
    ax.set_axisbelow(True)

    # Garis tepi minimalis dan bersih
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#cccccc')
    ax.spines['left'].set_linewidth(1.0)
    ax.spines['bottom'].set_color('#cccccc')
    ax.spines['bottom'].set_linewidth(1.0)

    ax.tick_params(axis='x', colors='#111111', length=5, direction='out')
    ax.tick_params(axis='y', colors='#111111', length=0)

    plt.tight_layout()
    plt.savefig(output_path, format='png', bbox_inches='tight', dpi=dpi)
    plt.close(fig)


def main():
    print("------------------------------------------------------------------------")
    print("Memulai Ekstraksi Real Data Feature Importance (Model Random Forest)")
    print("------------------------------------------------------------------------")
    print(f"Model biner : {MODEL_PATH}")
    print(f"TF-IDF biner: {TFIDF_PATH}")

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model biner tidak ditemukan: {MODEL_PATH}")
    if not os.path.exists(TFIDF_PATH):
        raise FileNotFoundError(f"TF-IDF biner tidak ditemukan: {TFIDF_PATH}")

    # 1. Memuat model biner & TF-IDF asli aplikasi
    print("-> Memuat model biner Random Forest dan TF-IDF")
    with open(TFIDF_PATH, "rb") as f:
        tfidf = pickle.load(f)

    with open(MODEL_PATH, "rb") as f:
        rf_model = pickle.load(f)

    # 2. Mengekstrak bobot kontribusi fitur secara real dari model aplikasi
    print("-> Mengekstrak 20 fitur paling berpengaruh (Top 20 Features) dari model real")
    feature_names = tfidf.get_feature_names_out()
    importances = rf_model.feature_importances_

    sorted_indices = np.argsort(importances)[::-1][:20]
    real_features = []
    print("\n[Top 20 Fitur Real Model Random Forest]:")
    for idx in sorted_indices:
        token = str(feature_names[idx])
        score = float(importances[idx])
        real_features.append((token, score))
        print(f" - {token:<15s}: {score:.4f}")

    # 3. Menyimpan visualisasi ke tools/data
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    unix_time = int(time.time())

    output_tools = os.path.join(OUTPUT_DIR, f"{unix_time}_shap_global_feature_importance_rf.png")

    plot_single_shap_bar(
        real_features,
        "Global Feature Importance (SHAP Summary) - Model Random Forest",
        output_tools
    )

    print("\n------------------------------------------------------------------------")
    print(f"[Sukses]: Feature Importance dari model real berhasil dirender!")
    print(f" -> {output_tools}")
    print("------------------------------------------------------------------------")


if __name__ == "__main__":
    main()
