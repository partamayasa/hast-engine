# tools/visualization/confusion_matrix.py
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
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix

warnings.filterwarnings("ignore", category=UserWarning)

# Direktori dinamis
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
DATASET_PATH = os.path.join(ROOT_DIR, "ai-model", "data", "cve_cvss4_dataset.csv")
MODEL_PATH = os.path.join(ROOT_DIR, "ai-model", "artifacts", "model_random_forest.pkl")
TFIDF_PATH = os.path.join(ROOT_DIR, "ai-model", "artifacts", "tfidf_vectorizer.pkl")
OUTPUT_DIR = os.path.join(ROOT_DIR, "tools", "data")

LABELS = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def get_severity_category(score):
    """Mengonversi skor numerik kontinu ke kategori skala keparahan CVSS v4.0."""
    if score == 0:
        return "NONE"
    elif 0.1 <= score <= 3.9:
        return "LOW"
    elif 4.0 <= score <= 6.9:
        return "MEDIUM"
    elif 7.0 <= score <= 8.9:
        return "HIGH"
    else:
        return "CRITICAL"


def plot_single_confusion_matrix(cm, labels, title, output_path, cmap="Blues"):
    """
    Menggambar dan menyimpan single Confusion Matrix dengan gaya visualisasi
    yang persis sesuai standar publikasi dan manuskrip skripsi (5x5).
    """
    plt.style.use('default')
    fig, ax = plt.subplots(figsize=(8.0, 7.0), dpi=600)

    # Matikan grid bawaan agar tidak memotong isi kotak
    ax.grid(False)
    ax.grid(False, which='major')

    # Hitung persentase per baris (True Severity Recall)
    cm_sum = np.sum(cm, axis=1, keepdims=True)
    cm_perc = np.divide(cm, cm_sum, out=np.zeros_like(cm, dtype=float), where=cm_sum != 0) * 100

    vmax = int(np.ceil(cm.max() / 250.0) * 250) if cm.max() > 0 else 2000
    cax = ax.imshow(cm, interpolation='nearest', cmap=cmap, vmin=0, vmax=vmax)

    # Colorbar gradasi warna di sebelah kanan (tanpa angka/ticks)
    cbar = fig.colorbar(cax, fraction=0.046, pad=0.04)
    cbar.set_ticks([])
    cbar.outline.set_visible(False)

    # Posisi dan orientasi tick labels
    tick_marks = np.arange(len(labels))
    ax.set_xticks(tick_marks)
    ax.set_yticks(tick_marks)
    ax.set_xticklabels(labels, fontsize=11, color='black')
    ax.set_yticklabels(labels, fontsize=11, rotation=90, va='center', color='black')

    # Sekat garis pembatas putih antar sel (hanya pada minor ticks)
    ax.set_xticks(np.arange(-0.5, len(labels), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(labels), 1), minor=True)
    ax.grid(True, which='minor', color='white', linestyle='-', linewidth=2.5)
    ax.tick_params(which='minor', bottom=False, left=False)
    ax.tick_params(which='major', bottom=False, left=False)

    # Anotasi teks: Jumlah Sampel dan Persentase per baris
    thresh = vmax / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            val = cm[i, j]
            pct = cm_perc[i, j]
            color = 'white' if val > thresh else 'black'
            ax.text(
                j, i,
                f"{val:,}\n({pct:.1f}%)",
                ha='center', va='center',
                color=color,
                fontsize=11
            )

    ax.set_title(title, fontsize=14, pad=18, color='black')
    ax.set_xlabel("Kategori Prediksi Model (Predicted Severity)", fontsize=12, labelpad=12, color='black')
    ax.set_ylabel("Kategori Keparahan Sebenarnya (True Severity)", fontsize=12, labelpad=12, color='black')

    for spine in ax.spines.values():
        spine.set_color('white')
        spine.set_linewidth(2.5)

    plt.tight_layout()
    plt.savefig(output_path, format='png', bbox_inches='tight', dpi=600)
    plt.close(fig)


def main():
    print("----------------------------------------------------------------")
    print("Memulai Evaluasi Real Data Confusion Matrix (CVSS v4.0)")
    print("----------------------------------------------------------------")
    print(f"Dataset path : {DATASET_PATH}")
    print(f"Model path   : {MODEL_PATH}")
    print(f"TF-IDF path  : {TFIDF_PATH}")

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Dataset tidak ditemukan: {DATASET_PATH}")
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model biner tidak ditemukan: {MODEL_PATH}")
    if not os.path.exists(TFIDF_PATH):
        raise FileNotFoundError(f"TF-IDF biner tidak ditemukan: {TFIDF_PATH}")

    # 1. Memuat TF-IDF & Model Random Forest asli dari aplikasi
    print("-> Memuat model biner Random Forest dan bobot TF-IDF asli")
    with open(TFIDF_PATH, "rb") as f:
        tfidf = pickle.load(f)

    with open(MODEL_PATH, "rb") as f:
        rf_model = pickle.load(f)

    # 2. Memuat dataset NVD asli
    print("-> Memuat dataset CVE CVSS v4.0 asli")
    df = pd.read_csv(DATASET_PATH)
    text_column = next(op for op in ['summary', 'description', 'desc', 'text'] if op in df.columns)
    score_column = next(op for op in ['cvss_score', 'cvss4_score', 'score', 'predicted_cvss4_score'] if op in df.columns)

    df_clean = df.dropna(subset=[text_column, score_column]).reset_index(drop=True)
    print(f"-> Dataframe valid: {len(df_clean):,} baris.")

    # 3. Transformasi fitur dan evaluasi test set (80/20)
    print("-> Mengekstrak fitur TF-IDF dari teks aktual")
    X_tfidf = tfidf.transform(df_clean[text_column])
    y_raw = df_clean[score_column].values

    _, X_test, _, y_test = train_test_split(X_tfidf, y_raw, test_size=0.2, random_state=42)

    print("-> Melakukan prediksi pada sampel uji aktual (20% populasi)")
    y_pred = np.clip(rf_model.predict(X_test), 0.0, 10.0)

    y_test_cat = [get_severity_category(s) for s in y_test]
    y_pred_cat = [get_severity_category(s) for s in y_pred]

    # 4. Menghitung Confusion Matrix 5x5 aktual
    cm = confusion_matrix(y_test_cat, y_pred_cat, labels=LABELS)
    print("\n[Confusion Matrix Aktual Terhitung]:")
    print(pd.DataFrame(cm, index=LABELS, columns=LABELS))

    # 5. Menyimpan visualisasi ke tools/data
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    unix_time = int(time.time())

    output_tools = os.path.join(OUTPUT_DIR, f"{unix_time}_confusion_matrix_random_forest.png")

    plot_single_confusion_matrix(
        cm,
        LABELS,
        "Confusion Matrix - Random Forest (CVSS v4.0)",
        output_tools,
        cmap="Blues"
    )

    print("\n------------------------------------------------------------------------")
    print(f"[Sukses]: Confusion matrix dari data real berhasil dirender!")
    print(f" -> {output_tools}")
    print("------------------------------------------------------------------------")


if __name__ == "__main__":
    main()
