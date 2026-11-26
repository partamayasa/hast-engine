# backend/core/roles.py
"""
Kendali akses berbasis peran (RBAC) untuk DSS HAST.

Satu-satunya sumber definisi peran dan hak akses: backend menegakkannya pada setiap endpoint,
sedangkan UI menerima daftar hak pengguna saat login untuk menampilkan atau mengunci kontrol.
Kunci "manager" dan "analyst" dipertahankan dari v2.0 agar akun yang sudah ada tetap berlaku.
"""

PERMISSIONS = {
    "users.manage": "Mengelola akun user dan role",
    "settings.manage": "Mengubah aturan prioritas, due date (SLA), bobot, dan AHP",
    "history.delete": "Menghapus session/scan history",
    "dss.save_run": "Mengunggah laporan, menilai temuan, menjalankan korelasi, dan mencatat rekomendasi",
    "decision.triage": "Mengisi tindak lanjut: status, penanggung jawab, due date, dampak bisnis, upaya",
    "decision.override_priority": "Mengubah prioritas yang direkomendasikan sistem",
    "decision.accept_risk": "Menetapkan status 'Risiko diterima'",
    "decision.update_progress": "Memperbarui progres perbaikan (Sedang dikerjakan / Selesai) dan catatan",
    "report.export": "Mengunduh laporan tindak lanjut (Excel)",
    "research.evaluate": "Menjalankan evaluasi DSS terhadap ranking pakar",
}

ROLES = {
    "admin": {
        "label": "Administrator",
        "description": "Pengelola sistem: seluruh hak, termasuk mengelola user dan role.",
        "permissions": set(PERMISSIONS),
    },
    "manager": {
        "label": "Manajer Keamanan",
        "description": "Pengambil keputusan: menetapkan kebijakan prioritas dan due date, menerima risiko, "
                       "mengubah prioritas, dan menghapus history.",
        "permissions": {"settings.manage", "history.delete", "dss.save_run", "decision.triage",
                        "decision.override_priority", "decision.accept_risk", "decision.update_progress",
                        "report.export", "research.evaluate"},
    },
    "analyst": {
        "label": "Analis Keamanan",
        "description": "Penilai temuan: mengisi tindak lanjut, mengubah prioritas, dan menandai false positive "
                       "atau ditunda. Tidak dapat menerima risiko.",
        "permissions": {"dss.save_run", "decision.triage", "decision.override_priority",
                        "decision.update_progress", "report.export", "research.evaluate"},
    },
    "developer": {
        "label": "Pengembang",
        "description": "Tim perbaikan: melihat prioritas dan memperbarui progres issue "
                       "(Sedang dikerjakan / Selesai) beserta catatan.",
        "permissions": {"decision.update_progress"},
    },
    "auditor": {
        "label": "Auditor",
        "description": "Pimpinan atau auditor: hanya membaca, termasuk audit trail dan export laporan.",
        "permissions": {"report.export"},
    },
}

ROLE_KEYS = tuple(ROLES)
# Status yang boleh ditetapkan pengguna yang hanya memiliki hak 'decision.update_progress' (pengembang).
PROGRESS_STATUSES = ("OPEN", "IN_PROGRESS", "RESOLVED")


def permissions_of(role: str) -> set[str]:
    return set(ROLES.get(role, {}).get("permissions", set()))


def has_permission(role: str, permission: str) -> bool:
    return permission in permissions_of(role)


def role_catalog() -> list[dict]:
    return [{"key": k, "label": v["label"], "description": v["description"],
             "permissions": sorted(v["permissions"])} for k, v in ROLES.items()]
