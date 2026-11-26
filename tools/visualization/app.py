#!/usr/bin/env python3
"""
tools/visualization/app.py

Master CLI Orchestrator untuk seluruh modul visualisasi model Random Forest
dan dataset penelitian CVSS v4.0.
"""

import os
import sys
import argparse

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from confusion_matrix import main as run_confusion_matrix
from shap_global_feature_importance import main as run_feature_importance
from shap_summary_beeswarm_plot import main as run_beeswarm_plot
from distribution_dataset_nvd import main as run_distribution


def main():
    parser = argparse.ArgumentParser(
        description="Tools Visualisasi Evaluasi Model Random Forest (CVSS v4.0)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Jalankan semua visualisasi Random Forest dan dataset secara berurutan."
    )
    parser.add_argument(
        "--confusion-matrix",
        action="store_true",
        help="Render Confusion Matrix 5x5 Random Forest."
    )
    parser.add_argument(
        "--feature-importance",
        action="store_true",
        help="Render Top-20 SHAP / Feature Importance Random Forest."
    )
    parser.add_argument(
        "--beeswarm",
        action="store_true",
        help="Render SHAP Summary Beeswarm Plot Random Forest."
    )
    parser.add_argument(
        "--distribution",
        action="store_true",
        help="Render Distribusi Dataset NVD CVSS v4.0."
    )

    args = parser.parse_args()

    # Jika tidak ada argumen khusus yang dipilih, tampilkan panduan atau opsi interaktif
    if not any([args.all, args.confusion_matrix, args.feature_importance, args.beeswarm, args.distribution]):
        print("====================================================================")
        print("   TOOLS VISUALISASI MODEL RANDOM FOREST & DATASET (CVSS v4.0)     ")
        print("====================================================================")
        print("Pilih modul visualisasi yang ingin dieksekusi:")
        print(" [1] Confusion Matrix (Random Forest)")
        print(" [2] Global Feature Importance (Random Forest)")
        print(" [3] SHAP Summary Beeswarm Plot (Random Forest)")
        print(" [4] Distribusi Severity Dataset NVD (CVSS v4.0)")
        print(" [5] Eksekusi Semua Visualisasi Sekaligus")
        print(" [0] Keluar")
        print("--------------------------------------------------------------------")
        
        choice = input("Masukkan pilihan (0-5) [default: 5]: ").strip()
        if choice == "1":
            args.confusion_matrix = True
        elif choice == "2":
            args.feature_importance = True
        elif choice == "3":
            args.beeswarm = True
        elif choice == "4":
            args.distribution = True
        elif choice == "0":
            print("Operasi dibatalkan.")
            return
        else:
            args.all = True

    if args.all or args.distribution:
        print("\n>>> Menjalankan Visualisasi Distribusi Dataset NVD")
        run_distribution()

    if args.all or args.confusion_matrix:
        print("\n>>> Menjalankan Visualisasi Confusion Matrix Random Forest")
        run_confusion_matrix()

    if args.all or args.feature_importance:
        print("\n>>> Menjalankan Visualisasi Global Feature Importance Random Forest")
        run_feature_importance()

    if args.all or args.beeswarm:
        print("\n>>> Menjalankan Visualisasi SHAP Beeswarm Plot Random Forest")
        run_beeswarm_plot()

    print("\n[Selesai]: Seluruh proses visualisasi Random Forest telah selesai.")


if __name__ == "__main__":
    main()

