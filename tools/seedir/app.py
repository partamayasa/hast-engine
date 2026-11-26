#!/usr/bin/env python3
"""
tools/seedir/app.py

Generator Struktur Direktori dan Visualisasi Pohon Proyek (Seedir).
Menyediakan opsi fleksibel untuk menampilkan file di root, folder level 1,
level 2 (standar manuskrip skripsi), hingga struktur penuh.
"""

import os
import sys
import time
import tempfile
import argparse

# Konfigurasi direktori cache matplotlib untuk mencegah peringatan permission
os.environ.setdefault("MPLCONFIGDIR", os.path.join(tempfile.gettempdir(), "matplotlib_seedir_cache"))

import seedir as sd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Direktori dasar
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "tools", "data")

# Konfigurasi pengecualian default (lingkungan virtual dan cache)
DEFAULT_EXCLUDE_FOLDERS = [
    '.git',
    '__pycache__',
    '.venv',
    'venv',
    'env',
    '.pytest_cache',
    '.streamlit',
    'node_modules'
]
DEFAULT_EXCLUDE_FILES = [
    '.DS_Store',
    'desktop.ini',
    'Thumbs.db',
    'ehthumbs.db'
]


def generate_tree_structure(depth_limit=2, folders_only=False, exclude_folders=None, exclude_files=None):
    """
    Menghasilkan representasi string pohon direktori menggunakan pustaka seedir.
    """
    if exclude_folders is None:
        exclude_folders = DEFAULT_EXCLUDE_FOLDERS
    if exclude_files is None:
        exclude_files = DEFAULT_EXCLUDE_FILES

    kwargs = {}
    if folders_only:
        kwargs['include_files'] = []

    tree_str = sd.seedir(
        PROJECT_ROOT,
        style='lines',
        depthlimit=depth_limit,
        exclude_folders=exclude_folders,
        exclude_files=exclude_files,
        sort=True,
        printout=False,
        **kwargs
    )
    return tree_str


def save_tree_outputs(tree_string, mode_label="TreeStructure"):
    """
    Menyimpan hasil representasi pohon ke format teks (.txt) dan gambar (.png).
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    unix_time = int(time.time())

    output_txt_path = os.path.join(OUTPUT_DIR, f"{unix_time}_{mode_label}.txt")
    output_png_path = os.path.join(OUTPUT_DIR, f"{unix_time}_{mode_label}.png")

    # 1. Simpan berkas teks (.txt)
    with open(output_txt_path, "w", encoding="utf-8") as f:
        f.write(tree_string)
    print(f"\n[Info] Berkas teks struktur disimpan di: {output_txt_path}")

    # 2. Render dan simpan berkas gambar beresolusi tinggi (.png)
    lines = tree_string.split('\n')
    num_lines = len(lines)

    plt.style.use('default')
    fig, ax = plt.subplots(figsize=(12, max(4.0, num_lines * 0.28)), dpi=600)
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')
    ax.axis('off')

    formatted_text = "\n".join(lines)

    ax.text(
        0.01, 0.99,
        formatted_text,
        fontfamily='monospace',
        fontsize=10.5,
        color='black',
        verticalalignment='top',
        horizontalalignment='left'
    )

    plt.savefig(output_png_path, bbox_inches='tight', facecolor=fig.get_facecolor(), dpi=600)
    plt.close(fig)
    print(f"[Info] Berkas gambar pohon disimpan di: {output_png_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Generator Visualisasi Pohon Direktori Proyek (Seedir)"
    )
    parser.add_argument(
        "-m", "--mode",
        type=int,
        choices=[1, 2, 3, 4],
        help="Mode tampilan: 1 (Level 1 Ringkas), 2 (Standar Skripsi: Root + Level 1 + Level 2), 3 (Level 3 Mendalam), 4 (Penuh Tanpa Batas)"
    )
    parser.add_argument(
        "-d", "--depth",
        type=int,
        default=None,
        help="Menentukan kedalaman pohon secara manual (contoh: 1, 2, 3, dst.)"
    )
    parser.add_argument(
        "-f", "--folders-only",
        action="store_true",
        help="Hanya menampilkan folder tanpa menampilkan berkas"
    )

    args = parser.parse_args()

    depth = args.depth
    folders_only = args.folders_only
    mode_label = "TreeStructure"

    if args.mode is not None:
        if args.mode == 1:
            depth = 1
            mode_label = "TreeStructure_Level1"
        elif args.mode == 2:
            depth = 2
            mode_label = "TreeStructure_Standard_Level2"
        elif args.mode == 3:
            depth = 3
            mode_label = "TreeStructure_Level3"
        elif args.mode == 4:
            depth = None
            mode_label = "TreeStructure_Full"
    elif depth is None:
        # Tampilan menu interaktif jika dieksekusi tanpa argumen CLI
        print("====================================================================")
        print("           GENERATOR STRUKTUR DIREKTORI PROYEK (SEEDIR)             ")
        print("====================================================================")
        print("Pilih opsi visualisasi pohon yang diinginkan:")
        print(" [1] Level 1 Ringkas (File di Root & Folder Level 1)")
        print(" [2] Standar Skripsi/Manuskrip (Root + Level 1 + Subfolder Level 2) [Rekomendasi]")
        print(" [3] Struktur Mendalam (Level 1 s.d. Level 3)")
        print(" [4] Struktur Penuh (Seluruh Direktori & File Tanpa Batas)")
        print(" [0] Keluar")
        print("--------------------------------------------------------------------")

        try:
            choice = input("Masukkan nomor pilihan (0-4) [default: 2]: ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = "2"

        if choice == "1":
            depth = 1
            mode_label = "TreeStructure_Level1"
        elif choice == "3":
            depth = 3
            mode_label = "TreeStructure_Level3"
        elif choice == "4":
            depth = None
            mode_label = "TreeStructure_Full"
        elif choice == "0":
            print("Operasi dibatalkan.")
            return
        else:
            depth = 2
            mode_label = "TreeStructure_Standard_Level2"

    print(f"\n-> Memproses pemindaian struktur proyek: {PROJECT_ROOT}")
    print(f"-> Parameter: Kedalaman (depth) = {depth if depth is not None else 'Penuh (Unlimited)'}, Hanya Folder = {folders_only}\n")

    tree_str = generate_tree_structure(depth_limit=depth, folders_only=folders_only)

    # Cetak hasil ke layar terminal
    print("--------------------------------------------------------------------")
    print(tree_str)
    print("--------------------------------------------------------------------")

    # Simpan output ke folder tools/data
    save_tree_outputs(tree_str, mode_label=mode_label)


if __name__ == '__main__':
    main()
