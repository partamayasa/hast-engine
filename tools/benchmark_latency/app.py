# tools/benchmark_latency/app.py
"""
Skrip Evaluasi Teknis: Pengukuran Latensi dan Waktu Respons Sistem
Digunakan untuk menguji performa endpoint backend FastAPI (/predict dan /predict/hybrid)
sesuai dengan Listing 4.5 pada naskah evaluasi sistem.
"""
import time
import requests

API_URL = "http://localhost:8000/predict"
HYBRID_URL = "http://localhost:8000/predict/hybrid"

# Payload uji temuan kerentanan
sample_single_payload = {
    "scanner_type": "SonarQube",
    "description": "SQL injection vulnerability in database authentication query parameter",
    "component": "auth_controller.py"
}

sample_hybrid_payload = {
    "sast_description": "SQL injection in user login query",
    "dast_description": "SQL injection vulnerability detected on login endpoint parameter",
    "cwe_id": "CWE-89",
    "model_engine": "Random Forest"
}


def measure_endpoint_latency(url, payload, test_name="Single Prediction"):
    """Mengukur latensi HTTP POST request dari client ke backend API."""
    print(f"\n--- Pengujian Latensi: {test_name} ({url}) ---")
    start_time = time.time()
    try:
        response = requests.post(url, json=payload, timeout=10)
        end_time = time.time()

        latency_seconds = end_time - start_time
        latency_ms = latency_seconds * 1000

        print(f"HTTP Status Code    : {response.status_code}")
        print(f"Total Response Time : {latency_seconds:.4f} detik ({latency_ms:.2f} ms)")

        if response.status_code == 200:
            res_data = response.json()
            print(f"Skor Prediksi AI    : {res_data.get('predicted_cvss4_score')}")
            print(f"Tingkat Keparahan   : {res_data.get('predicted_severity')}")
            if "is_verified_true_positive" in res_data:
                print(f"Verifikasi HAST     : {res_data.get('is_verified_true_positive')}")
        else:
            print(f"Peringatan/Error    : {response.text}")

        return latency_seconds
    except requests.exceptions.ConnectionError:
        print("[Error]: Gagal terhubung ke backend API (http://localhost:8000).")
        print("Pastikan backend FastAPI sedang berjalan (uvicorn backend.api:app --reload).")
        return None


if __name__ == "__main__":
    print("==================================================================")
    print("Pengujian Latensi dan Waktu Respons Endpoint Backend (Listing 4.5)")
    print("==================================================================")

    # 1. Uji Endpoint Single Prediction
    measure_endpoint_latency(API_URL, sample_single_payload, test_name="Single Prediction (/predict)")

    # 2. Uji Endpoint Hybrid Correlation Prediction
    measure_endpoint_latency(HYBRID_URL, sample_hybrid_payload, test_name="Hybrid Prediction (/predict/hybrid)")

    print("\n==================================================================")
    print("Pengujian Selesai.")

