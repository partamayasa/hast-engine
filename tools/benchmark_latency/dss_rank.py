# tools/benchmark_latency/dss_rank.py
"""
Benchmark latensi untuk endpoint ranking DSS (POST /api/v1/dss/rank, persist=false).
Terpisah dari app.py, yang mereproduksi pengukuran yang dikutip dalam naskah tesis.

Pemakaian:
    uv run python tools/benchmark_latency/dss_rank.py --batch-id HAST-1794896040 --runs 20 --method TOPSIS
"""
import argparse
import statistics
import time

import requests


def main():
    p = argparse.ArgumentParser()
    # 127.0.0.1, bukan "localhost": di Windows, resolusi localhost dapat menambah ~2 detik per permintaan (fallback IPv6).
    p.add_argument("--api", default="http://127.0.0.1:8000")
    p.add_argument("--batch-id", required=True)
    p.add_argument("--method", default=None)
    p.add_argument("--runs", type=int, default=20)
    a = p.parse_args()

    body = {"batch_id": a.batch_id, "persist": False}
    if a.method:
        body["method"] = a.method
    times, n_alt = [], None
    for _ in range(a.runs):
        t0 = time.perf_counter()
        r = requests.post(f"{a.api}/api/v1/dss/rank", json=body, timeout=60)
        times.append((time.perf_counter() - t0) * 1000)
        r.raise_for_status()
        n_alt = len(r.json()["items"])
    times.sort()
    p95 = times[max(0, int(round(0.95 * len(times))) - 1)]
    print(f"Endpoint /api/v1/dss/rank  batch={a.batch_id}  alternatif={n_alt}  n={a.runs}")
    print(f"median={statistics.median(times):.2f} ms  mean={statistics.mean(times):.2f} ms  "
          f"p95={p95:.2f} ms  min={times[0]:.2f} ms  max={times[-1]:.2f} ms")


if __name__ == "__main__":
    main()
