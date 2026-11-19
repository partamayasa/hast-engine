from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
import pandas as pd
import numpy as np
import pickle
import time
import json
import os
import sys
import warnings

# Redam peringatan kosmetik terkait nama fitur matriks sparse antarpustaka
warnings.filterwarnings("ignore", category=UserWarning)

# Impor pustaka ML dan NLP yang dibutuhkan

print("--------------------------")
print("Memulai Proses Model Final")
print("--------------------------")

# Ambil jalur direktori 'training' tempat skrip ini berada
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Naik satu tingkat ke direktori akar 'ai-model'
AI_MODEL_ROOT = os.path.dirname(CURRENT_DIR)

# Atur jalur absolut untuk masukan, keluaran, dan artefak model agar aman dijalankan dari direktori kerja mana pun
DATA_PATH = os.path.join(AI_MODEL_ROOT, "data", "cve_cvss4_dataset.csv")
RF_MODEL_PATH = os.path.join(AI_MODEL_ROOT, "artifacts", "model_random_forest.pkl")
TFIDF_PATH = os.path.join(AI_MODEL_ROOT, "artifacts", "tfidf_vectorizer.pkl")
EVAL_PATH = os.path.join(AI_MODEL_ROOT, "data", "model_training_result.json")

# Atur jalur berkas konfigurasi utama di ai-model/
CONFIG_PATH = os.path.join(AI_MODEL_ROOT, "config", "ai_config.json")

if not os.path.exists(CONFIG_PATH):
    print(f"\n[Critical Error]: Berkas konfigurasi utama '{CONFIG_PATH}' tidak ditemukan!")
    print("-> Eksekusi dihentikan paksa untuk memastikan tidak ada parameter ilegal yang berjalan.\n")
    import sys
    sys.exit(1)

# Muat konfigurasi eksperimen AI dari berkas JSON eksternal
with open(CONFIG_PATH, "r") as f:
    ai_config = json.load(f)

print(f"-> Berhasil memuat konfigurasi eksternal dari: '{CONFIG_PATH}'")


def get_severity_category(score):
    # Fungsi bantu untuk mengonversi skor CVSS v4.0 numerik menjadi kategori keparahan berupa teks
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


# Muat dataset yang dihimpun dari NVD
try:
    df_nvd = pd.read_csv(DATA_PATH)

    # Deteksi otomatis kolom teks deskripsi berdasarkan pilihan kata kunci kandidat
    text_column = None
    for option in ['summary', 'description', 'desc', 'text']:
        if option in df_nvd.columns:
            text_column = option
            break

    # Deteksi otomatis kolom skor target CVSS
    score_column = None
    for option in ['cvss_score', 'cvss4_score', 'score', 'predicted_cvss4_score']:
        if option in df_nvd.columns:
            score_column = option
            break

    print(f"-> Berhasil memuat dataset utama dari: '{DATA_PATH}'")
    print(f"-> Menggunakan kolom deskripsi: '{text_column}' dan target skor: '{score_column}'")
except FileNotFoundError:
    print(f"[Eror]: Berkas dataset tidak ditemukan di '{DATA_PATH}'!")
    print("Pastikan Anda mengeksekusi skrip ini dari folder utama proyek.")
    exit()

# Pembersihan data: hapus baris dengan nilai hilang (NaN) pada kolom teks atau skor
df_nvd = df_nvd.dropna(subset=[text_column, score_column]).reset_index(drop=True)
X_text = df_nvd[text_column]
y_raw = df_nvd[score_column].values.reshape(-1, 1)

print(f"-> Populasi data yang akan dipelajari AI: {len(df_nvd)} entri.")
print("-------------------------------------------")
print("Ekstraksi Fitur Teks (TF-IDF Vectorization)")
print("-------------------------------------------")

# Fit TF-IDF Vectorizer dengan batas kosakata dinamis dari konfigurasi
max_features = ai_config.get("preprocessing", {}).get("max_features", 5000)
tfidf = TfidfVectorizer(stop_words='english', max_features=max_features)
X_tfidf = tfidf.fit_transform(X_text)
print(f"-> Matriks TF-IDF berhasil dibentuk dengan ukuran: {X_tfidf.shape}")
print("----------------------------------------------")
print("Proses Evaluasi Teknis Validasi Internal Model")
print("----------------------------------------------")
scheme = ai_config.get("preprocessing", {}).get("comparison_scheme", "split")
scheme_label = "5-Fold Cross-Validation" if scheme == "k-fold" else "Train-Test Split (80:20)"
print(f"-> Menggunakan Skema Validasi: {scheme_label}")

# Pembagian data latih-uji (80:20) untuk simulasi dan evaluasi internal sebelum produksi
X_train_sub, X_test_sub, y_train_sub_raw, y_test_sub_raw = train_test_split(
    X_tfidf, y_raw, test_size=0.2, random_state=42
)

# Ambil parameter model dan prapemrosesan dari objek konfigurasi JSON
rf_params = ai_config.get("model_hyperparameters", {}).get("random_forest", {})

y_train_sub_transformed = y_train_sub_raw.flatten()

# Tentukan hyperparameter model kandidat untuk validasi dan perbandingan di Streamlit
eval_models = {
    "Random Forest Regressor": RandomForestRegressor(
        n_estimators=rf_params.get("n_estimators", 100),
        criterion=rf_params.get("criterion", "squared_error"),
        max_depth=rf_params.get("max_depth", None),
        random_state=42,
        n_jobs=-1
    )
}

# Dictionary untuk menyimpan metrik kinerja dan log waktu pelatihan setiap model
evaluation_metrics = {}

for name, model in eval_models.items():
    print(f"-> Mengevaluasi performa internal: {name}")

    if scheme == "k-fold":
        from sklearn.model_selection import KFold
        from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
        kf = KFold(n_splits=5, shuffle=True, random_state=42)
        acc_list, prec_list, rec_list, f1_list = [], [], [], []
        mae_list, rmse_list, r2_list = [], [], []
        fold_times = []
        fold_records = []

        fold_counter = 1
        for train_idx, test_idx in kf.split(X_tfidf):
            X_tr, X_te = X_tfidf[train_idx], X_tfidf[test_idx]
            y_tr, y_te = y_raw[train_idx], y_raw[test_idx]

            t_start = time.time()
            model.fit(X_tr, y_tr.flatten())
            training_time = time.time() - t_start
            fold_times.append(training_time)

            y_pred = model.predict(X_te)
            y_pred = np.clip(y_pred, 0.0, 10.0)

            y_te_flat = y_te.flatten()
            y_te_cat = [get_severity_category(s) for s in y_te_flat]
            y_pred_cat = [get_severity_category(s) for s in y_pred]

            acc_list.append(accuracy_score(y_te_cat, y_pred_cat))
            prec_list.append(precision_score(y_te_cat, y_pred_cat, average='macro', zero_division=0))
            rec_list.append(recall_score(y_te_cat, y_pred_cat, average='macro', zero_division=0))
            f1_list.append(f1_score(y_te_cat, y_pred_cat, average='macro', zero_division=0))
            mae_list.append(mean_absolute_error(y_te_flat, y_pred))
            rmse_list.append(float(np.sqrt(mean_squared_error(y_te_flat, y_pred))))
            r2_list.append(r2_score(y_te_flat, y_pred))

            fold_acc = acc_list[-1]
            fold_prec = prec_list[-1]
            fold_rec = rec_list[-1]
            fold_f1 = f1_list[-1]
            fold_mae = mae_list[-1]
            fold_rmse = rmse_list[-1]
            fold_r2 = r2_list[-1]

            fold_records.append({
                "fold": fold_counter,
                "accuracy": float(round(fold_acc, 4)),
                "precision": float(round(fold_prec, 4)),
                "recall": float(round(fold_rec, 4)),
                "f1_score": float(round(fold_f1, 4)),
                "mae": float(round(fold_mae, 4)),
                "rmse": float(round(fold_rmse, 4)),
                "r2_score": float(round(fold_r2, 4)),
                "training_time": float(round(training_time, 2))
            })

            print(f"   -> Fold {fold_counter}/5 : Accuracy: {fold_acc:.4f} | Precision: {fold_prec:.4f} | Recall: {fold_rec:.4f} | F1-Score: {fold_f1:.4f} | Exec Time: {training_time:.2f}s")
            fold_counter += 1

        accuracy_value = np.mean(acc_list)
        precision_value = np.mean(prec_list)
        recall_value = np.mean(rec_list)
        f1_value = np.mean(f1_list)
        mae_value = np.mean(mae_list)
        rmse_value = np.mean(rmse_list)
        r2_value = np.mean(r2_list)
        eval_duration = np.sum(fold_times)

        labels_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        confusion_matrix_values = confusion_matrix(y_te_cat, y_pred_cat, labels=labels_order).tolist()
    else:
        # Catat waktu mulai pelatihan internal
        start_eval_time = time.time()

        # Fit model evaluasi
        model.fit(X_train_sub, y_train_sub_transformed)
        y_pred_continuous = model.predict(X_test_sub)

        # Batasi prediksi kontinu agar tetap dalam batas logis CVSS v4.0 (0.0 sampai 10.0)
        y_pred_continuous = np.clip(y_pred_continuous, 0.0, 10.0)
        eval_duration = time.time() - start_eval_time
        y_test_sub_final = y_test_sub_raw.flatten()

        # Konversi nilai kontinu (skor) menjadi kategori teks untuk menghitung metrik klasifikasi
        labels_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        y_test_categorical = [get_severity_category(s) for s in y_test_sub_final]
        y_pred_categorical = [get_severity_category(s) for s in y_pred_continuous]

        # Hitung metrik kinerja klasifikasi untuk perbandingan
        accuracy_value = accuracy_score(y_test_categorical, y_pred_categorical)
        precision_value = precision_score(y_test_categorical, y_pred_categorical, average='macro', zero_division=0)
        recall_value = recall_score(y_test_categorical, y_pred_categorical, average='macro', zero_division=0)
        f1_value = f1_score(y_test_categorical, y_pred_categorical, average='macro', zero_division=0)
        confusion_matrix_values = confusion_matrix(y_test_categorical, y_pred_categorical, labels=labels_order).tolist()

        # Hitung metrik kinerja regresi (MAE, RMSE, R2 Score)
        from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
        mae_value = mean_absolute_error(y_test_sub_final, y_pred_continuous)
        rmse_value = float(np.sqrt(mean_squared_error(y_test_sub_final, y_pred_continuous)))
        r2_value = r2_score(y_test_sub_final, y_pred_continuous)

    # Simpan metrik yang dihitung dan durasi pelatihan ke dictionary utama
    evaluation_metrics[name] = {
        "training_time": float(round(eval_duration, 2)),  # Dipakai untuk grafik waktu proses di Streamlit
        "accuracy": float(accuracy_value),
        "precision": float(precision_value),
        "recall": float(recall_value),
        "f1_score": float(f1_value),
        "mae": float(round(mae_value, 4)),
        "rmse": float(round(rmse_value, 4)),
        "r2_score": float(round(r2_value, 4)),
        "confusion_matrix": confusion_matrix_values,
        "folds": fold_records if scheme == "k-fold" else []
    }

    if scheme == "k-fold":
        print(f"    - Mean Accuracy: {accuracy_value:.4f} | Mean Precision: {precision_value:.4f} | Mean Recall: {recall_value:.4f} | Mean F1-Score: {f1_value:.4f} | Total Time: {eval_duration:.2f}s")
    else:
        print(f"    - Accuracy: {accuracy_value:.4f} | Precision: {precision_value:.4f} | Recall: {recall_value:.4f} | F1-Score: {f1_value:.4f} | Exec Time: {eval_duration:.2f}s")

print("------------------------------------------")
print("Pelatihan Model Pada 100% Dataset Populasi")
print("------------------------------------------")

# Latih model produksi akhir untuk Random Forest Regressor
print("Sedang melatih Random Forest Regressor")
final_rf_model = RandomForestRegressor(
    n_estimators=rf_params.get("n_estimators", 100),
    criterion=rf_params.get("criterion", "squared_error"),
    max_depth=rf_params.get("max_depth", None),
    random_state=42,
    n_jobs=-1
)
final_rf_model.fit(X_tfidf, y_raw.flatten())

print("-----------------------------------------------")
print("Menyimpan Model, Vectorizer, & Evaluasi ke Disk")
print("-----------------------------------------------")

# Buat folder artefak secara otomatis bila direktori tujuan belum ada di disk
folder_artifacts = os.path.dirname(RF_MODEL_PATH)
if folder_artifacts and not os.path.exists(folder_artifacts):
    os.makedirs(folder_artifacts, exist_ok=True)

# Simpan berkas model Random Forest akhir (.pkl)
with open(RF_MODEL_PATH, 'wb') as f:
    pickle.dump(final_rf_model, f)
print(f"-> Model Random Forest berhasil disimpan di: '{RF_MODEL_PATH}'")

# Simpan objek TF-IDF Vectorizer (.pkl) untuk tokenisasi teks di aplikasi backend
with open(TFIDF_PATH, 'wb') as f:
    pickle.dump(tfidf, f)
print(f"-> Bobot TF-IDF berhasil disimpan di: '{TFIDF_PATH}'")

# Simpan log evaluasi internal (pembagian 80/20) ke berkas JSON
training_manifest = {
    "test_id": int(time.time()),
    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
    "results": evaluation_metrics
}
with open(EVAL_PATH, 'w') as f:
    json.dump(training_manifest, f, indent=4)
print(f"-> Berkas manifes evaluasi latih-uji internal berhasil dibuat di: '{EVAL_PATH}'")

# -------------------------------------------------------------------------
# Simpan metadata riset dan evaluasi model ke basis data secara otomatis
# -------------------------------------------------------------------------
print("-----------------------------------------------------")
print("Sinkronisasi Metadata Riset & Evaluasi ke Database")
print("-----------------------------------------------------")
try:
    PROJECT_ROOT = os.path.dirname(AI_MODEL_ROOT)
    
    # 1. Metadata populasi dataset NVD
    scores_arr = df_nvd[score_column].values
    tot_samples = len(scores_arr)
    tr_samples = int(tot_samples * 0.8)
    te_samples = tot_samples - tr_samples
    
    meta_dict = {
        "total_samples": tot_samples,
        "train_samples": tr_samples,
        "test_samples": te_samples,
        "train_ratio": 0.8,
        "test_ratio": 0.2,
        "mean_score": float(np.mean(scores_arr)),
        "std_score": float(np.std(scores_arr)),
        "min_score": float(np.min(scores_arr)),
        "max_score": float(np.max(scores_arr)),
        "validation_scheme": scheme_label
    }
    
    # 2. Distribusi kelas keparahan CVSS v4.0
    sevs = [get_severity_category(s) for s in scores_arr]
    s_counts = pd.Series(sevs).value_counts()
    range_map = {
        'MEDIUM': '4.0 - 6.9',
        'HIGH': '7.0 - 8.9',
        'LOW': '0.1 - 3.9',
        'CRITICAL': '9.0 - 10.0',
        'NONE': '0.0'
    }
    class_dist = []
    for s_name, count_val in s_counts.items():
        prop = round((count_val / tot_samples) * 100, 2)
        class_dist.append({
            "severity": s_name,
            "count": int(count_val),
            "proportion": prop,
            "score_range": range_map.get(s_name, "-")
        })
    
    # 3. Ekstrak fitur penyumbang teratas (SHAP / Feature Importances)
    top_rf_features = {}
    if hasattr(final_rf_model, "feature_importances_"):
        feature_names = tfidf.get_feature_names_out()
        importances = final_rf_model.feature_importances_
        sorted_indices = np.argsort(importances)[::-1][:10]
        for idx in sorted_indices:
            top_rf_features[str(feature_names[idx])] = float(round(importances[idx], 4))
            
    # 4. Evaluasi model Random Forest
    rf_eval = evaluation_metrics.get("Random Forest Regressor", {})
    eval_dict = {
        "algorithm": "Random Forest Regressor",
        "accuracy": rf_eval.get("accuracy", 0.0),
        "precision": rf_eval.get("precision", 0.0),
        "recall": rf_eval.get("recall", 0.0),
        "f1_score": rf_eval.get("f1_score", 0.0),
        "mae": rf_eval.get("mae", 0.0),
        "rmse": rf_eval.get("rmse", 0.0),
        "r2_score": rf_eval.get("r2_score", 0.0),
        "training_time_seconds": rf_eval.get("training_time", 0.0),
        "confusion_matrix": rf_eval.get("confusion_matrix", []),
        "shap_features": top_rf_features
    }
    
    if PROJECT_ROOT not in sys.path:
        sys.path.append(PROJECT_ROOT)
    # v2: metrik riset ditulis melalui repositori backend (satu-satunya pemilik basis data).
    from backend.core.settings import get_settings
    from backend.db.bootstrap import init_database
    from backend.db.session import session_scope
    from backend.repositories import research as research_repo
    db_url = get_settings().database_url
    init_database(db_url)
    with session_scope(db_url) as db_session:
        research_repo.save_dataset_metadata(db_session, meta_dict, class_dist)
        research_repo.save_model_evaluation(db_session, eval_dict)
    print(f"-> [Database Update]: Metadata dataset & metrik model berhasil disimpan ke database: '{db_url}'")
except Exception as e:
    print(f"-> [Database Warning]: Gagal memperbarui database SQLite: {e}")

print("-----------------------------------------------------")
print("[Sukses] [Status]: Mesin AI & Database Riset Siap!")
print("-----------------------------------------------------")
