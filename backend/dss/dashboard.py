# backend/dss/dashboard.py
"""
Ringkasan dasbor DSS: angka kunci, beban kerja, tenggat, dan sebaran temuan.

Modul ini murni (tanpa I/O, tanpa basis data, tanpa model ML). Masukannya adalah daftar keputusan hasil
`dss_repo.decision_to_dict` dan statistik batch hasil `history_repo.batch_stats`, sehingga dapat diuji langsung.
Dasbor hanya merangkum data yang sudah ada; tidak ada skor atau prioritas baru yang dihitung di sini.
"""
import datetime
from collections import Counter

from backend.dss.evaluation import agreement_rate
from backend.dss.recommender import PRIORITY_LABELS, STATUSES

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")
PRIORITY_ORDER = ("P1", "P2", "P3", "P4")
UNASSIGNED = "Belum ditugaskan"
NO_PRIORITY = "Tanpa prioritas"


def _days_left(due: str | None, today: datetime.date) -> int | None:
    if not due:
        return None
    try:
        return (datetime.date.fromisoformat(due) - today).days
    except ValueError:
        return None


def _kpis(decisions: list[dict], today: datetime.date, due_soon_days: int) -> dict:
    open_items = [d for d in decisions if not d["is_closed"]]
    closed = len(decisions) - len(open_items)
    due_soon = sum(1 for d in open_items
                   if not d["is_overdue"] and (left := _days_left(d["sla_due_date"], today)) is not None
                   and 0 <= left <= due_soon_days)
    decided = [d for d in decisions if d["decided_by"]]
    agreement = agreement_rate([(d["recommended_action"], d["chosen_action"] or d["recommended_action"])
                                for d in decided])
    return {
        "total_issues": len(decisions),
        "open_issues": len(open_items),
        "p1_open": sum(1 for d in open_items if d["priority"] == "P1"),
        "in_progress": sum(1 for d in open_items if d["status"] == "IN_PROGRESS"),
        "overdue": sum(1 for d in open_items if d["is_overdue"]),
        "due_soon": due_soon,
        "due_soon_days": due_soon_days,
        "closed_issues": closed,
        "closure_rate": round(closed / len(decisions), 4) if decisions else None,
        "unassigned_open": sum(1 for d in open_items if not d["owner"]),
        "needs_review_open": sum(1 for d in open_items if d.get("needs_review")),
        "agreement": agreement,
    }


def _priority_status(decisions: list[dict]) -> list[dict]:
    """Jumlah isu per prioritas efektif x status; urutan prioritas P1-P4 lalu tanpa prioritas."""
    counts = Counter((d["priority"] or NO_PRIORITY, d["status"]) for d in decisions)
    order = list(PRIORITY_ORDER) + [NO_PRIORITY]
    status_order = list(STATUSES)
    rows = [{"priority": p, "priority_label": PRIORITY_LABELS.get(p, p), "status": s,
             "status_label": STATUSES.get(s, s), "count": n} for (p, s), n in counts.items()]
    return sorted(rows, key=lambda r: (order.index(r["priority"]) if r["priority"] in order else len(order),
                                       status_order.index(r["status"]) if r["status"] in status_order else 99))


def _top_cwe(decisions: list[dict], limit: int) -> list[dict]:
    """CWE dengan isu terbuka terbanyak; nilai seri diurutkan menurut kode CWE agar deterministik."""
    open_items = [d for d in decisions if not d["is_closed"]]
    counts = Counter(d["cwe_id"] or "-" for d in open_items)
    p1 = Counter(d["cwe_id"] or "-" for d in open_items if d["priority"] == "P1")
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    return [{"cwe_id": c, "open": n, "p1_open": p1.get(c, 0)} for c, n in ranked]


def _owner_load(decisions: list[dict]) -> list[dict]:
    """Beban kerja terbuka per penanggung jawab, termasuk isu yang belum ditugaskan."""
    load: dict[str, dict] = {}
    for d in decisions:
        if d["is_closed"]:
            continue
        name = d["owner"] or UNASSIGNED
        row = load.setdefault(name, {"owner": name, "open": 0, "p1_open": 0, "overdue": 0})
        row["open"] += 1
        row["p1_open"] += d["priority"] == "P1"
        row["overdue"] += bool(d["is_overdue"])
    return sorted(load.values(), key=lambda r: (-r["open"], r["owner"] == UNASSIGNED, r["owner"]))


def _deadlines(decisions: list[dict], today: datetime.date, limit: int) -> list[dict]:
    """Isu terbuka bertenggat, diurutkan dari yang paling mendesak (lewat tenggat lebih dulu)."""
    rows = []
    for d in decisions:
        left = _days_left(d["sla_due_date"], today)
        if d["is_closed"] or left is None:
            continue
        rows.append({"decision_key": d["decision_key"], "title": d["title"], "cwe_id": d["cwe_id"],
                     "priority": d["priority"], "priority_label": d["priority_label"],
                     "status_label": d["status_label"], "owner": d["owner"],
                     "sla_due_date": d["sla_due_date"], "days_left": left, "is_overdue": d["is_overdue"]})
    rows.sort(key=lambda r: (r["days_left"], PRIORITY_ORDER.index(r["priority"])
                             if r["priority"] in PRIORITY_ORDER else 9, r["title"] or ""))
    return rows[:limit]


def _latest_scans(batch_stats: list[dict]) -> list[dict]:
    """Batch terbaru untuk setiap jenis pemindaian (masukan sudah terurut dari yang terbaru)."""
    seen, out = set(), []
    for b in batch_stats:
        if b["scanner_type"] in seen:
            continue
        seen.add(b["scanner_type"])
        out.append(b)
    return out


def build_summary(decisions: list[dict], batch_stats: list[dict], today: datetime.date | None = None,
                  due_soon_days: int = 7, top_n: int = 8, deadline_limit: int = 10) -> dict:
    """
    Menyusun seluruh data dasbor dari keputusan dan statistik batch.

    Parameter:
        decisions: daftar keputusan (format `decision_to_dict`, opsional dengan kunci `needs_review`).
        batch_stats: statistik per batch, terurut dari yang terbaru (format `history_repo.batch_stats`).
        today: tanggal acuan perhitungan tenggat; bawaan tanggal hari ini.
        due_soon_days: batas hari untuk kategori "tenggat dekat".
        top_n: jumlah CWE yang ditampilkan.
        deadline_limit: jumlah maksimum baris daftar tenggat.

    Mengembalikan:
        dict berisi `kpis`, `priority_status`, `top_cwe`, `owner_load`, `deadlines`, `latest_scans`,
        `scan_trend`, dan `severity_order`.
    """
    today = today or datetime.date.today()
    return {
        "generated_for": today.isoformat(),
        "kpis": _kpis(decisions, today, due_soon_days),
        "priority_status": _priority_status(decisions),
        "top_cwe": _top_cwe(decisions, top_n),
        "owner_load": _owner_load(decisions),
        "deadlines": _deadlines(decisions, today, deadline_limit),
        "latest_scans": _latest_scans(batch_stats),
        "scan_trend": list(reversed(batch_stats)),
        "severity_order": list(SEVERITY_ORDER),
    }
