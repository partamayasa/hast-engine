# tools/visualization/shap_summary_beeswarm_plot.py
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
import shap

warnings.filterwarnings("ignore", category=UserWarning)

# Direktori dinamis
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
DATASET_PATH = os.path.join(ROOT_DIR, "ai-model", "data", "cve_cvss4_dataset.csv")
MODEL_PATH = os.path.join(ROOT_DIR, "ai-model", "artifacts", "model_random_forest.pkl")
TFIDF_PATH = os.path.join(ROOT_DIR, "ai-model", "artifacts", "tfidf_vectorizer.pkl")
OUTPUT_DIR = os.path.join(ROOT_DIR, "tools", "data")


def main():
    print("---------------------------------------------------------")
    print("Memulai Evaluasi Real Data SHAP Summary Beeswarm Plot")
    print("---------------------------------------------------------")
    print(f"Dataset path : {DATASET_PATH}")
    print(f"Model path   : {MODEL_PATH}")
    print(f"TF-IDF path  : {TFIDF_PATH}")

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Dataset tidak ditemukan: {DATASET_PATH}")
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

    feature_names = tfidf.get_feature_names_out()

    # 2. Memuat sampel teks dari subset data uji (Test Set 20% populasi)
    print("-> Memuat subset data uji aktual (Test Set 20% populasi, random_state=42)")
    df = pd.read_csv(DATASET_PATH)
    text_column = next(op for op in ['summary', 'description', 'desc', 'text'] if op in df.columns)
    score_column = next(op for op in ['cvss_score', 'cvss4_score', 'score', 'predicted_cvss4_score'] if op in df.columns)

    df_clean = df.dropna(subset=[text_column, score_column]).reset_index(drop=True)
    _, df_test = train_test_split(df_clean, test_size=0.2, random_state=42)
    sample_texts = df_test[text_column].iloc[:250].tolist()

    X_sample = tfidf.transform(sample_texts).toarray()

    # 3. Menghitung atribusi SHAP aktual menggunakan TreeExplainer
    print("-> Menghitung nilai SHAP aktual menggunakan TreeExplainer (250 sampel data uji murni)")
    t_start = time.time()
    explainer = shap.TreeExplainer(rf_model)
    shap_vals = explainer.shap_values(X_sample, check_additivity=False)
    if isinstance(shap_vals, list):
        shap_vals = shap_vals[0]
    print(f"-> Kalkulasi SHAP selesai dalam {time.time() - t_start:.2f} detik.")

    # 4. Merender visualisasi SHAP beeswarm plot ke tools/data
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    unix_time = int(time.time())

    output_tools = os.path.join(OUTPUT_DIR, f"{unix_time}_shap_summary_beeswarm_rf.png")

    plt.style.use('default')
    fig = plt.figure(figsize=(9.0, 10.0), dpi=600)

    shap.summary_plot(
        shap_vals,
        X_sample,
        feature_names=feature_names,
        max_display=20,
        plot_type="dot",
        show=False
    )

    plt.title("SHAP Summary Beeswarm Plot - Model Random Forest", fontsize=13, pad=16, color='black')
    plt.xlabel("Nilai SHAP (Dampak terhadap Prediksi Skor CVSS v4.0)", fontsize=11, labelpad=10, color='black')
    plt.tick_params(axis='both', colors='black')

    plt.tight_layout()
    plt.savefig(output_tools, format='png', bbox_inches='tight', dpi=600)
    plt.close(fig)

    print("\n---------------------------------------------------------------------------------")
    print(f"[Sukses]: SHAP Beeswarm Plot dari data real berhasil dirender!")
    print(f" -> {output_tools}")
    print("---------------------------------------------------------------------------------")


if __name__ == "__main__":
    main()
