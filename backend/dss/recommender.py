# backend/dss/recommender.py
"""
Lapisan prioritas berbasis aturan. Ranking menjawab "dengan urutan apa"; aturan menjawab "seberapa mendesak,
apa yang dilakukan, dan kapan" dalam istilah yang dipakai tim keamanan (P1-P4).

Aturan dievaluasi berurutan; aturan pertama yang cocok dipakai dan ID-nya dikembalikan untuk keterlacakan.
Hari SLA adalah KEBIJAKAN ORGANISASI yang diisi di dss_config (null = tanpa tenggat).
"""
import datetime

ACTIONS = {
    "REMEDIATE_NOW": "Perbaiki segera",
    "REMEDIATE_SCHEDULED": "Jadwalkan perbaikan",
    "PLAN": "Masukkan ke rencana",
    "REVIEW_OR_ACCEPT": "Pantau / terima risiko",
    "ACCEPT_RISK": "Terima risiko",
    "FALSE_POSITIVE": "Bukan masalah (false positive)",
    "DEFER": "Tunda",
}
# Tingkat prioritas per aksi (angka lebih kecil = lebih mendesak). Aksi analis di luar tingkat ini diurutkan terakhir.
PRIORITY_OF_ACTION = {"REMEDIATE_NOW": "P1", "REMEDIATE_SCHEDULED": "P2", "PLAN": "P3", "REVIEW_OR_ACCEPT": "P4"}
ACTION_OF_PRIORITY = {v: k for k, v in PRIORITY_OF_ACTION.items()}
PRIORITY_LABELS = {
    "P1": "P1 · Segera",
    "P2": "P2 · Terjadwal",
    "P3": "P3 · Direncanakan",
    "P4": "P4 · Pantau",
}
STATUSES = {
    "OPEN": "Belum ditangani",
    "IN_PROGRESS": "Sedang dikerjakan",
    "RESOLVED": "Selesai diperbaiki",
    "ACCEPTED_RISK": "Risiko diterima",
    "FALSE_POSITIVE": "Bukan masalah (false positive)",
    "DEFERRED": "Ditunda",
}
CLOSED_STATUSES = ("RESOLVED", "ACCEPTED_RISK", "FALSE_POSITIVE")
BUSINESS_IMPACT = {5: "Tinggi", 3: "Sedang", 1: "Rendah"}
EFFORT = {1: "Kecil", 2: "Sedang", 3: "Besar"}


def _matches(cond: dict, ctx: dict) -> bool:
    if "severity_in" in cond and ctx["severity"] not in [s.upper() for s in cond["severity_in"]]:
        return False
    if "true_positive" in cond and bool(ctx["true_positive"]) != bool(cond["true_positive"]):
        return False
    if "min_hybrid_score" in cond and ctx["hybrid_score"] < float(cond["min_hybrid_score"]):
        return False
    if "min_business_impact" in cond and ctx.get("business_impact", 3) < float(cond["min_business_impact"]):
        return False
    if "max_rank" in cond and ctx["rank"] > int(cond["max_rank"]):
        return False
    if "min_preference" in cond and ctx["preference"] < float(cond["min_preference"]):
        return False
    return True


def recommend(ctx: dict, rules: list[dict], sla_days: dict | None = None,
              today: datetime.date | None = None) -> dict:
    """
    ctx: {severity, true_positive, hybrid_score, rank, preference, business_impact}.
    Mengembalikan {action, action_label, priority, priority_label, rule_id, sla_days, sla_due_date}.
    """
    if not rules:
        raise ValueError("Konfigurasi DSS tidak memiliki aturan rekomendasi.")
    for rule in rules:
        if _matches(rule.get("when", {}), ctx):
            action = rule["action"]
            if action not in ACTIONS:
                raise ValueError(f"Aksi rekomendasi tidak dikenal pada aturan {rule.get('id')}: {action}")
            priority = rule.get("priority") or PRIORITY_OF_ACTION.get(action, "P4")
            days = (sla_days or {}).get(action)
            due = None
            if days is not None:
                due = ((today or datetime.date.today()) + datetime.timedelta(days=int(days))).isoformat()
            return {"action": action, "action_label": ACTIONS[action], "priority": priority,
                    "priority_label": PRIORITY_LABELS.get(priority, priority), "rule_id": rule.get("id"),
                    "rule_text": rule.get("text"), "sla_days": days, "sla_due_date": due}
    raise ValueError("Tidak ada aturan rekomendasi yang cocok; tambahkan aturan penampung (when: {}).")
